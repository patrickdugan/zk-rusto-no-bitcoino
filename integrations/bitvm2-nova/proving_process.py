"""Bounded Windows process execution for a caller-configured trusted executable.

This module does not select, build, prove, verify or schedule a workload.
The child is created suspended, assigned to a non-breakaway Job Object, then
resumed. Closing the noninherited job handle kills its process tree. Both
process and aggregate job COMMIT limits are configured; these are not RSS.
Stdout/stderr are drained through bounded pipes into exclusive-new owned files.
No command line or environment values are included in results or exceptions.

Win32 contracts: learn.microsoft.com/windows/win32/api/winnt/
ns-winnt-jobobject_extended_limit_information and
ns-winnt-jobobject_associate_completion_port. Ordinary job notifications are
best effort; a memory-limit reason means a limit signal was actually observed.
Hard memory limits remain enforced even if an allocation-failure message is not
delivered. An application's zero exit is never treated as proof verification.

Linux is deliberately unsupported until an equivalently explicit implementation
is added: there is no unbounded or shell-based fallback.
"""
from dataclasses import asdict, dataclass
import ctypes as C
import json
import math
import os
from pathlib import Path
import queue
import stat
import subprocess
import threading
import time


class RunnerError(RuntimeError):
    """Launch, configuration or cleanup failure; never a proof rejection."""


@dataclass(frozen=True)
class ProcessResult:
    succeeded: bool
    exit_code: int | None
    termination_reason: str
    elapsed_seconds: float
    stdout_path: str
    stderr_path: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    output_limit_bytes: int
    memory_limit_bytes: int
    peak_job_commit_bytes: int
    peak_process_commit_bytes: int
    peak_process_working_set_bytes: int | None
    memory_limit_signal_observed: bool
    memory_limit_signal_sources: tuple[str, ...]
    process_count: int
    process_exit_codes: tuple[int, ...]
    process_accounting_complete: bool
    thread_environment_limit: int
    platform: str = 'windows-job-object'
    memory_accounting: str = 'committed virtual memory; working set reported separately'
    working_set_accounting: str = 'maximum queried per-process peak working set; not aggregate RSS'

    def summary(self):
        return asdict(self)


# Fixed-width Win32 types keep the structure definitions auditable on64-bit
# Windows and importable without loading DLLs on other platforms.
DWORD, BOOL, WORD = C.c_uint32, C.c_int32, C.c_uint16
SIZE_T, HANDLE, PTR = C.c_size_t, C.c_void_p, C.c_void_p


class _BasicLimits(C.Structure):
    _fields_ = [('PerProcessUserTimeLimit',C.c_int64),('PerJobUserTimeLimit',C.c_int64),
        ('LimitFlags',DWORD),('MinimumWorkingSetSize',SIZE_T),('MaximumWorkingSetSize',SIZE_T),
        ('ActiveProcessLimit',DWORD),('Affinity',SIZE_T),('PriorityClass',DWORD),('SchedulingClass',DWORD)]


class _IoCounters(C.Structure):
    _fields_ = [(name,C.c_uint64) for name in ('ReadOperationCount','WriteOperationCount',
        'OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]


class _ExtendedLimits(C.Structure):
    _fields_ = [('BasicLimitInformation',_BasicLimits),('IoInfo',_IoCounters),
        ('ProcessMemoryLimit',SIZE_T),('JobMemoryLimit',SIZE_T),
        ('PeakProcessMemoryUsed',SIZE_T),('PeakJobMemoryUsed',SIZE_T)]


class _Accounting(C.Structure):
    _fields_ = [(name,C.c_int64) for name in ('TotalUserTime','TotalKernelTime',
        'ThisPeriodTotalUserTime','ThisPeriodTotalKernelTime')]+[(name,DWORD) for name in
        ('TotalPageFaultCount','TotalProcesses','ActiveProcesses','TotalTerminatedProcesses')]


class _PortAssociation(C.Structure):
    _fields_ = [('CompletionKey',PTR),('CompletionPort',HANDLE)]


class _Security(C.Structure):
    _fields_ = [('nLength',DWORD),('lpSecurityDescriptor',PTR),('bInheritHandle',BOOL)]


class _Startup(C.Structure):
    _fields_ = [('cb',DWORD),('lpReserved',C.c_wchar_p),('lpDesktop',C.c_wchar_p),
        ('lpTitle',C.c_wchar_p)]+[(name,DWORD) for name in ('dwX','dwY','dwXSize','dwYSize',
        'dwXCountChars','dwYCountChars','dwFillAttribute','dwFlags')]+[
        ('wShowWindow',WORD),('cbReserved2',WORD),('lpReserved2',PTR),
        ('hStdInput',HANDLE),('hStdOutput',HANDLE),('hStdError',HANDLE)]


class _StartupEx(C.Structure):
    _fields_ = [('StartupInfo',_Startup),('lpAttributeList',PTR)]


class _ProcessInfo(C.Structure):
    _fields_ = [('hProcess',HANDLE),('hThread',HANDLE),('dwProcessId',DWORD),('dwThreadId',DWORD)]


class _MemoryCounters(C.Structure):
    _fields_ = [('cb',DWORD),('PageFaultCount',DWORD)]+[(name,SIZE_T) for name in
        ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
         'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]


class _Win:
    def __init__(self):
        if os.name != 'nt':
            raise RunnerError('Windows Job Object execution is required; no fallback was launched')
        self.k = C.WinDLL('kernel32',use_last_error=True)
        self.p = C.WinDLL('psapi',use_last_error=True)
        def bind(dll,name,result,args):
            function=getattr(dll,name);function.restype=result;function.argtypes=args
            setattr(self,name,function)
        bind(self.k,'CloseHandle',BOOL,[HANDLE])
        bind(self.k,'CreateJobObjectW',HANDLE,[PTR,C.c_wchar_p])
        bind(self.k,'SetInformationJobObject',BOOL,[HANDLE,C.c_int,PTR,DWORD])
        bind(self.k,'QueryInformationJobObject',BOOL,[HANDLE,C.c_int,PTR,DWORD,PTR])
        bind(self.k,'AssignProcessToJobObject',BOOL,[HANDLE,HANDLE])
        bind(self.k,'TerminateJobObject',BOOL,[HANDLE,C.c_uint32])
        bind(self.k,'TerminateProcess',BOOL,[HANDLE,C.c_uint32])
        bind(self.k,'CreateIoCompletionPort',HANDLE,[HANDLE,HANDLE,SIZE_T,DWORD])
        bind(self.k,'GetQueuedCompletionStatus',BOOL,[HANDLE,C.POINTER(DWORD),C.POINTER(SIZE_T),C.POINTER(PTR),DWORD])
        bind(self.k,'CreatePipe',BOOL,[C.POINTER(HANDLE),C.POINTER(HANDLE),C.POINTER(_Security),DWORD])
        bind(self.k,'SetHandleInformation',BOOL,[HANDLE,DWORD,DWORD])
        bind(self.k,'CreateFileW',HANDLE,[C.c_wchar_p,DWORD,DWORD,C.POINTER(_Security),DWORD,DWORD,HANDLE])
        bind(self.k,'InitializeProcThreadAttributeList',BOOL,[PTR,DWORD,DWORD,C.POINTER(SIZE_T)])
        bind(self.k,'UpdateProcThreadAttribute',BOOL,[PTR,DWORD,SIZE_T,PTR,SIZE_T,PTR,PTR])
        bind(self.k,'DeleteProcThreadAttributeList',None,[PTR])
        bind(self.k,'CreateProcessW',BOOL,[C.c_wchar_p,C.c_wchar_p,PTR,PTR,BOOL,DWORD,PTR,
            C.c_wchar_p,C.POINTER(_StartupEx),C.POINTER(_ProcessInfo)])
        bind(self.k,'ResumeThread',DWORD,[HANDLE])
        bind(self.k,'WaitForSingleObject',DWORD,[HANDLE,DWORD])
        bind(self.k,'GetExitCodeProcess',BOOL,[HANDLE,C.POINTER(DWORD)])
        bind(self.k,'OpenProcess',HANDLE,[DWORD,BOOL,DWORD])
        bind(self.k,'IsProcessInJob',BOOL,[HANDLE,HANDLE,C.POINTER(BOOL)])
        bind(self.k,'ReadFile',BOOL,[HANDLE,PTR,DWORD,C.POINTER(DWORD),PTR])
        bind(self.k,'OpenThread',HANDLE,[DWORD,BOOL,DWORD])
        bind(self.k,'CancelSynchronousIo',BOOL,[HANDLE])
        bind(self.p,'GetProcessMemoryInfo',BOOL,[HANDLE,C.POINTER(_MemoryCounters),DWORD])

    @staticmethod
    def error(operation):
        return RunnerError(f'{operation} failed (winerror {C.get_last_error()})')

    def check(self,value,operation):
        if not value:raise self.error(operation)
        return value

    def close(self,handle):
        if handle and handle != C.c_void_p(-1).value:
            self.check(self.CloseHandle(handle),'CloseHandle')

    def query(self,job,kind,structure):
        value=structure()
        self.check(self.QueryInformationJobObject(job,kind,C.byref(value),C.sizeof(value),None),
                   'QueryInformationJobObject')
        return value


class _Capture:
    def __init__(self,limit):
        self.limit=limit
        self.reserved=0
        self.observed=[0,0]
        self.lock=threading.Lock()
        self.overflow=threading.Event()
        self.failed=threading.Event()

    def accept(self,index,data,output):
        with self.lock:
            self.observed[index]+=len(data)
            allowed=min(len(data),self.limit-self.reserved)
            self.reserved+=allowed
            if allowed < len(data):self.overflow.set()
        offset=0
        while offset < allowed:
            written=output.write(data[offset:allowed])
            if written is None or written <= 0:raise OSError('bounded output write failed')
            offset+=written


class _PipeReader(threading.Thread):
    def __init__(self,api,handle,capture,index,output):
        super().__init__(name=f'bounded-output-{index}',daemon=True)
        self.api,self.handle,self.capture,self.index,self.output=api,handle,capture,index,output
        self.cancelled=False

    def run(self):
        try:
            buffer=C.create_string_buffer(65536)
            count=DWORD()
            while True:
                ok=self.api.ReadFile(self.handle,buffer,len(buffer),C.byref(count),None)
                if not ok:
                    error=C.get_last_error()
                    if error in (109,38) or (self.cancelled and error==995):break
                    self.capture.failed.set();break
                if not count.value:break
                self.capture.accept(self.index,buffer.raw[:count.value],self.output)
        except BaseException:
            self.capture.failed.set()
        finally:
            try:self.api.close(self.handle)
            except BaseException:self.capture.failed.set()
            self.handle=None

    def finish(self):
        self.join(5)
        if self.is_alive():
            self.cancelled=True
            handle=self.api.OpenThread(0x0001,False,self.native_id)
            if handle:
                try:self.api.CancelSynchronousIo(handle)
                finally:self.api.close(handle)
            self.join(5)
        if self.is_alive():raise RunnerError('output reader cleanup did not complete')


class _ProcessIds(C.Structure):
    _fields_=[('NumberOfAssignedProcesses',DWORD),('NumberOfProcessIdsInList',DWORD),
              ('ProcessIdList',SIZE_T*64)]


class _JobObserver(threading.Thread):
    """Retain process handles at birth, independently of controller polling.

    Job packets are best effort, so active-PID snapshots supplement them and an
    unmatched authoritative TotalProcesses count still fails closed. Validating
    IsProcessInJob also rejects a PID that exited and was recycled before open.
    """
    def __init__(self,api,job,port,known):
        super().__init__(name='bounded-job-observer',daemon=True)
        self.api,self.job,self.port,self.known=api,job,port,known
        self.lock=threading.Lock()
        self.stopping=threading.Event()
        self.notices=queue.SimpleQueue()
        self.sources=set()

    def snapshot(self):
        with self.lock:return dict(self.known)

    def memory_sources(self):
        with self.lock:return set(self.sources)

    def track(self,pid):
        if not pid:return
        with self.lock:
            if pid in self.known:return
            if len(self.known)>=64:
                self.notices.put('process_tracking_limit');return
            handle=self.api.OpenProcess(0x00100000|0x1000,False,pid)
            if not handle:
                self.notices.put('process_accounting_incomplete');return
            member=BOOL()
            if not self.api.IsProcessInJob(handle,self.job,C.byref(member)) or not member.value:
                self.api.close(handle)
                self.notices.put('process_accounting_incomplete');return
            self.known[pid]=handle

    def discover_active(self):
        value=_ProcessIds()
        self.api.check(self.api.QueryInformationJobObject(self.job,3,C.byref(value),C.sizeof(value),None),
                       'query active job process IDs')
        if value.NumberOfAssignedProcesses>64 or value.NumberOfProcessIdsInList>64:
            self.notices.put('process_tracking_limit');return
        for pid in value.ProcessIdList[:value.NumberOfProcessIdsInList]:self.track(int(pid))

    def drain(self):
        messages=[]
        while True:
            try:messages.append(self.notices.get_nowait())
            except queue.Empty:return messages

    def run(self):
        try:
            drained=0
            while True:
                message,key,pid=DWORD(),SIZE_T(),PTR()
                wait=0 if self.stopping.is_set() else 50
                ok=self.api.GetQueuedCompletionStatus(self.port,C.byref(message),C.byref(key),C.byref(pid),wait)
                if not ok:
                    if C.get_last_error()==258:
                        if self.stopping.is_set():return
                        continue
                    self.notices.put('job_notification_failure');return
                if key.value!=1:
                    self.notices.put('job_notification_failure');return
                if message.value in (9,10):
                    with self.lock:self.sources.add('process_memory' if message.value==9 else 'job_memory')
                    self.notices.put('memory_limit')
                elif message.value==3:self.notices.put('process_limit')
                elif message.value==6:self.track(pid.value)
                elif message.value==8:self.notices.put('abnormal_process_exit')
                if self.stopping.is_set():
                    drained+=1
                    if drained>1024:
                        self.notices.put('job_notification_failure');return
        except BaseException:
            self.notices.put('job_notification_failure')

    def finish(self):
        self.stopping.set()
        if self.ident is not None:
            self.join(2)
            if self.is_alive():raise RunnerError('job observer cleanup did not complete')


def _integer(value,minimum,maximum,label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise RunnerError(f'invalid {label}')
    return value


def _directory(path,label):
    try:
        value=Path(path).resolve(strict=True)
        if not value.is_dir():raise RunnerError(f'{label} must be an existing directory')
    except (OSError,TypeError,ValueError) as error:
        raise RunnerError(f'{label} directory is unavailable') from error
    return value


def _log_path(path,root):
    try:
        value=Path(path)
        if '..' in value.parts:raise RunnerError('log path aliases are forbidden')
        if not value.is_absolute():value=root/value
        parent=value.parent.resolve(strict=True)
        if not parent.is_relative_to(root):raise RunnerError('log path must remain beneath owned_root')
        value=parent/value.name
        if value.exists() or value.is_symlink():raise RunnerError('log files must be exclusive-new')
        return value
    except (OSError,TypeError,ValueError) as error:
        raise RunnerError('invalid owned log path') from error


def _new_log(path):
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)
    descriptor=None
    try:
        descriptor=os.open(path,flags,0o600)
        information=os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode) or information.st_nlink!=1:
            raise RunnerError('new log is not an unaliased regular file')
        os.set_inheritable(descriptor,False)
        return os.fdopen(descriptor,'wb',buffering=0)
    except BaseException as error:
        if descriptor is not None:
            try:os.close(descriptor)
            except OSError:pass
        if isinstance(error,OSError):raise RunnerError('exclusive owned log creation failed') from error
        raise


def _environment(threads):
    environment=dict(os.environ,RAYON_NUM_THREADS=str(threads),CUDA_VISIBLE_DEVICES='')
    if any('\0' in key or '=' in key or '\0' in value for key,value in environment.items()):
        raise RunnerError('invalid inherited environment encoding')
    block='\0'.join(f'{key}={environment[key]}' for key in sorted(environment,key=str.upper))+'\0\0'
    if len(block)>1<<20:raise RunnerError('inherited environment byte budget')
    return C.create_unicode_buffer(block)


def run_bounded(executable,arguments,*,cwd,owned_root,stdout_path,stderr_path,
                memory_mib,wall_seconds,threads,output_limit_bytes=16<<20,
                poll_seconds=0.05,cancel_event=None):
    """Run one trusted executable with bounded Windows process-tree resources.

    ``arguments`` excludes argv[0]. Output paths are exclusive-new and beneath
    mandatory existing ``owned_root``; they need not be beneath source ``cwd``.
    Thread count configures RAYON_NUM_THREADS, not an OS thread-count limit.
    Nonzero, timeout, cap, descendant failure and incomplete accounting return
    failed results. Launch/job setup/cleanup failures raise RunnerError after
    terminating any child. Nothing here interprets failure as proof rejection.
    """
    if os.name!='nt':raise RunnerError('Windows Job Object execution required; no process was launched')
    try:
        selected=Path(executable)
        if not selected.is_absolute():raise RunnerError('trusted executable must be absolute')
        selected=selected.resolve(strict=True)
        if not selected.is_file() or selected.suffix.lower()!='.exe':
            raise RunnerError('trusted native executable file required')
    except (OSError,TypeError,ValueError) as error:
        raise RunnerError('trusted executable is unavailable') from error
    if type(arguments) not in (list,tuple) or any(type(arg) is not str or '\0' in arg for arg in arguments):
        raise RunnerError('explicit string argv sequence required')
    if len(arguments)>4096:raise RunnerError('argument count budget')
    command=subprocess.list2cmdline([str(selected),*arguments])
    try:command_units=len(command.encode('utf-16-le'))//2
    except UnicodeError as error:raise RunnerError('invalid Windows argv encoding') from error
    if command_units>=32767:raise RunnerError('Windows command-line size budget')
    memory=_integer(memory_mib,16,1<<20,'memory_mib')*(1<<20)
    _integer(threads,1,1024,'threads')
    _integer(output_limit_bytes,1,1<<30,'output_limit_bytes')
    if (type(wall_seconds) not in (int,float) or not math.isfinite(wall_seconds)
            or not 0 < wall_seconds <= 7*86400):raise RunnerError('invalid wall_seconds')
    if type(poll_seconds) not in (int,float) or not math.isfinite(poll_seconds) or not .005<=poll_seconds<=.5:
        raise RunnerError('invalid poll_seconds')
    if cancel_event is not None and not isinstance(cancel_event,threading.Event):
        raise RunnerError('cancel_event must be a threading.Event')
    if cancel_event is not None and cancel_event.is_set():
        raise RunnerError('cancelled before launch; no process was created')
    if memory > (1 << (8*C.sizeof(SIZE_T)))-1:raise RunnerError('memory limit exceeds native SIZE_T')
    working=_directory(cwd,'cwd');root=_directory(owned_root,'owned_root')
    output=_log_path(stdout_path,root);errors=_log_path(stderr_path,root)
    if os.path.normcase(str(output))==os.path.normcase(str(errors)):
        raise RunnerError('stdout and stderr paths must differ')
    with _new_log(output) as out:
        with _new_log(errors) as err:
            return _windows(selected,command,working,output,errors,out,err,memory,float(wall_seconds),
                            threads,output_limit_bytes,float(poll_seconds),cancel_event)


def _windows(executable,command,cwd,stdout_path,stderr_path,out,err,memory,wall,threads,limit,poll,cancel):
    api=_Win()
    job=port=None
    info=_ProcessInfo()
    child_handles=[]
    pipe_reads=[]
    readers=[]
    attribute=None
    attribute_initialized=False
    assigned=resumed=False
    known={}
    codes={}
    signals=set()
    capture=_Capture(limit)
    reason=None
    terminated=False
    termination_started=None
    peak_working=None
    started=time.monotonic()
    deadline=started+wall
    accounting=None
    limits=None
    result=None
    cleanup_error=None
    observer=None
    try:
        job=api.check(api.CreateJobObjectW(None,None),'CreateJobObjectW')
        limits=_ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags=0x2000|0x100|0x200|0x400|0x8
        limits.BasicLimitInformation.ActiveProcessLimit=64
        limits.ProcessMemoryLimit=memory;limits.JobMemoryLimit=memory
        api.check(api.SetInformationJobObject(job,9,C.byref(limits),C.sizeof(limits)),'SetInformationJobObject')
        port=api.check(api.CreateIoCompletionPort(C.c_void_p(-1).value,None,0,1),'CreateIoCompletionPort')
        association=_PortAssociation(1,port)
        api.check(api.SetInformationJobObject(job,7,C.byref(association),C.sizeof(association)),
                  'associate job completion port')
        security=_Security(C.sizeof(_Security),None,True)
        for _ in range(2):
            read,write=HANDLE(),HANDLE()
            api.check(api.CreatePipe(C.byref(read),C.byref(write),C.byref(security),65536),'CreatePipe')
            pipe_reads.append(read.value);child_handles.append(write.value)
            api.check(api.SetHandleInformation(read,1,0),'pipe inheritance')
        null=api.CreateFileW('NUL',0x80000000,3,C.byref(security),3,0x80,None)
        if not null or null==C.c_void_p(-1).value:raise api.error('open null stdin')
        child_handles.append(null)
        size=SIZE_T()
        api.InitializeProcThreadAttributeList(None,1,0,C.byref(size))
        if not size.value:raise api.error('attribute list sizing')
        attribute=C.create_string_buffer(size.value)
        api.check(api.InitializeProcThreadAttributeList(attribute,1,0,C.byref(size)),'attribute list initialization')
        attribute_initialized=True
        inherited=(HANDLE*3)(null,child_handles[0],child_handles[1])
        api.check(api.UpdateProcThreadAttribute(attribute,0,0x20002,inherited,C.sizeof(inherited),None,None),
                  'explicit inherited handle list')
        startup=_StartupEx()
        startup.StartupInfo.cb=C.sizeof(startup)
        startup.StartupInfo.dwFlags=0x100|1
        startup.StartupInfo.wShowWindow=0
        startup.StartupInfo.hStdInput=null
        startup.StartupInfo.hStdOutput=child_handles[0]
        startup.StartupInfo.hStdError=child_handles[1]
        startup.lpAttributeList=C.cast(attribute,PTR)
        environment=_environment(threads)
        mutable_command=C.create_unicode_buffer(command)
        flags=0x00000004|0x08000000|0x00000400|0x00080000
        api.check(api.CreateProcessW(str(executable),mutable_command,None,None,True,flags,
            C.cast(environment,PTR),str(cwd),C.byref(startup),C.byref(info)),'CreateProcessW')
        # No user code can run until successful assignment and ResumeThread.
        known[int(info.dwProcessId)]=info.hProcess
        for handle in child_handles:api.close(handle)
        child_handles.clear()
        observer=_JobObserver(api,job,port,known)
        observer.start()
        api.check(api.AssignProcessToJobObject(job,info.hProcess),'AssignProcessToJobObject')
        assigned=True
        for index,(handle,file) in enumerate(zip(tuple(pipe_reads),(out,err),strict=True)):
            reader=_PipeReader(api,handle,capture,index,file)
            reader.start();readers.append(reader)
            pipe_reads.remove(handle)
        if cancel is not None and cancel.is_set():
            raise RunnerError('cancelled before resume; child user code did not run')
        previous=api.ResumeThread(info.hThread)
        if previous!=1:raise api.error('ResumeThread unexpected suspend count')
        resumed=True
        api.close(info.hThread);info.hThread=None

        def messages():
            nonlocal reason
            signals.update(observer.memory_sources())
            for notice in observer.drain():
                reason='memory_limit' if notice=='memory_limit' else (reason or notice)

        def process_statuses():
            nonlocal reason,peak_working
            for pid,handle in observer.snapshot().items():
                waited=api.WaitForSingleObject(handle,0)
                if waited==0 and pid not in codes:
                    code=DWORD();api.check(api.GetExitCodeProcess(handle,C.byref(code)),'GetExitCodeProcess')
                    codes[pid]=int(code.value)
                    if code.value:reason=reason or ('nonzero_exit' if pid==info.dwProcessId else 'descendant_nonzero_exit')
                elif waited==0xffffffff:raise api.error('WaitForSingleObject')
                counters=_MemoryCounters();counters.cb=C.sizeof(counters)
                if api.GetProcessMemoryInfo(handle,C.byref(counters),C.sizeof(counters)):
                    peak_working=max(peak_working or 0,int(counters.PeakWorkingSetSize))

        settled=None
        while True:
            observer.discover_active()
            messages()
            if capture.overflow.is_set():reason=reason or 'output_limit'
            if capture.failed.is_set():reason=reason or 'output_io_failure'
            if cancel is not None and cancel.is_set():reason=reason or 'cancelled'
            if time.monotonic()>=deadline:reason=reason or 'timeout'
            process_statuses()
            if reason and not terminated:
                api.check(api.TerminateJobObject(job,0xe0000001),'TerminateJobObject')
                terminated=True
                termination_started=time.monotonic()
            accounting=api.query(job,1,_Accounting)
            if accounting.ActiveProcesses==0 and int(info.dwProcessId) in codes:
                if settled is None:settled=time.monotonic()
                # Drain completion packets after the last process exit, without
                # asserting that Windows guarantees every notification packet.
                if time.monotonic()-settled>=min(.1,2*poll):break
            else:settled=None
            if terminated and time.monotonic()>termination_started+10:
                raise RunnerError('job did not terminate within cleanup bound')
            time.sleep(poll)
        for reader in readers:reader.finish()
        observer.finish()
        process_statuses()
        messages()
        if capture.overflow.is_set():reason=reason or 'output_limit'
        if capture.failed.is_set():reason=reason or 'output_io_failure'
        complete=(int(accounting.TotalProcesses)==len(known)==len(codes))
        if not complete:reason=reason or 'process_accounting_incomplete'
        limits=api.query(job,9,_ExtendedLimits)
        root_code=codes.get(int(info.dwProcessId))
        reason=reason or ('completed' if root_code==0 else 'nonzero_exit')
        result=ProcessResult(reason=='completed' and root_code==0,root_code,reason,
            time.monotonic()-started,str(stdout_path),str(stderr_path),
            os.fstat(out.fileno()).st_size,os.fstat(err.fileno()).st_size,
            capture.observed[0],capture.observed[1],limit,memory,
            int(limits.PeakJobMemoryUsed),int(limits.PeakProcessMemoryUsed),peak_working,
            bool(signals),tuple(sorted(signals)),int(accounting.TotalProcesses),
            tuple(codes[pid] for pid in sorted(codes)),complete,threads)
    finally:
        # Closing the last noninherited job handle is a second kill guarantee.
        # On assignment failure the child is still suspended and is killed
        # directly before any primary thread can be resumed.
        def cleanup(function):
            nonlocal cleanup_error
            try:function()
            except BaseException as error:cleanup_error=cleanup_error or error
        def stop_root():
            if assigned and job:
                api.check(api.TerminateJobObject(job,0xe0000002),'cleanup TerminateJobObject')
            elif info.hProcess and api.WaitForSingleObject(info.hProcess,0)!=0:
                api.check(api.TerminateProcess(info.hProcess,0xe0000002),'cleanup TerminateProcess')
        cleanup(stop_root)
        if observer is not None:cleanup(observer.finish)
        for handle in child_handles:cleanup(lambda handle=handle:api.close(handle))
        child_handles.clear()
        if job:
            def close_job():
                nonlocal job
                api.close(job)
                job=None
            cleanup(close_job)
        def confirm_root():
            if info.hProcess and api.WaitForSingleObject(info.hProcess,5000)!=0:
                api.TerminateProcess(info.hProcess,0xe0000002)
                if api.WaitForSingleObject(info.hProcess,5000)!=0:
                    raise RunnerError('root process termination could not be confirmed')
        cleanup(confirm_root)
        for reader in readers:cleanup(reader.finish)
        for handle in pipe_reads:cleanup(lambda handle=handle:api.close(handle))
        pipe_reads.clear()
        if attribute_initialized:cleanup(lambda:api.DeleteProcThreadAttributeList(attribute))
        # Each process handle is closed once, including the root handle.
        handles=set(known.values())
        if info.hProcess:handles.add(info.hProcess)
        for handle in [*handles,info.hThread,job,port]:cleanup(lambda handle=handle:api.close(handle))
        if cleanup_error:raise RunnerError('bounded process cleanup failed') from cleanup_error
    return result


def _self_test():
    """Small generic Python children only. Never builds or invokes a prover."""
    import sys
    import tempfile
    import unittest
    from unittest.mock import patch
    class Tests(unittest.TestCase):
        def setUp(self):
            workspace=Path(__file__).resolve().parent
            base=workspace/'results'
            base.mkdir(exist_ok=True)
            base=base.resolve(strict=True)
            if base.parent!=workspace:raise RunnerError('self-test output root escapes workspace')
            self.temporary=tempfile.TemporaryDirectory(prefix='process-unit-',dir=base)
            self.root=Path(self.temporary.name).resolve()
            if self.root.parent!=base:raise RunnerError('self-test temporary path escapes owned root')
            self.addCleanup(self.temporary.cleanup)
            self.sequence=0
        def child(self,source,**options):
            self.sequence+=1
            return run_bounded(Path(sys.executable).resolve(),['-c',source],cwd=self.root,
                owned_root=self.root,stdout_path=self.root/f'{self.sequence}.out',
                stderr_path=self.root/f'{self.sequence}.err',memory_mib=96,
                wall_seconds=options.pop('wall_seconds',5),threads=1,**options)
        def test_success_and_nonzero(self):
            result=self.child("import os,sys;print(os.environ['RAYON_NUM_THREADS']);sys.stderr.write('ok')")
            self.assertTrue(result.succeeded,result.summary())
            self.assertEqual(result.exit_code,0)
            self.assertEqual((result.stdout_bytes,result.stderr_bytes),(3,2))
            self.assertGreater(result.peak_job_commit_bytes,0)
            self.assertGreater(result.peak_process_commit_bytes,0)
            self.assertTrue(result.process_accounting_complete)
            failed=self.child('raise SystemExit(7)')
            self.assertFalse(failed.succeeded)
            self.assertEqual(failed.exit_code,7)
        def test_timeout_and_exact_disk_output_cap(self):
            result=self.child('import time;time.sleep(10)',wall_seconds=.2)
            self.assertFalse(result.succeeded)
            self.assertEqual(result.termination_reason,'timeout')
            result=self.child("import os;os.write(1,b'x'*8192);os.write(2,b'y'*8192)",output_limit_bytes=1024)
            self.assertFalse(result.succeeded)
            self.assertEqual(result.termination_reason,'output_limit')
            self.assertLessEqual(result.stdout_bytes+result.stderr_bytes,1024)
        def test_job_memory_limit_is_failure(self):
            result=self.child('import time\ntry:\n x=bytearray(256<<20)\nexcept MemoryError:\n time.sleep(.5)\n')
            self.assertFalse(result.succeeded,result.summary())
            self.assertEqual(result.termination_reason,'memory_limit')
        def test_output_alias_and_existing_files_reject_before_launch(self):
            existing=self.root/'existing';existing.write_bytes(b'preserve')
            with self.assertRaises(RunnerError):
                run_bounded(Path(sys.executable).resolve(),[],cwd=self.root,owned_root=self.root,
                    stdout_path=existing,stderr_path=self.root/'other',memory_mib=96,wall_seconds=1,threads=1)
            self.assertEqual(existing.read_bytes(),b'preserve')
        def test_timeout_kills_descendant_before_delayed_marker(self):
            marker=self.root/'escaped'
            source="import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',\"import time,pathlib;time.sleep(1);pathlib.Path('escaped').write_text('bad')\"]);time.sleep(10)"
            result=self.child(source,wall_seconds=.25)
            self.assertFalse(result.succeeded)
            time.sleep(1.1)
            self.assertFalse(marker.exists())
        def test_assignment_and_resume_failures_never_run_child_user_code(self):
            for operation in ('AssignProcessToJobObject','ResumeThread'):
                api=_Win()
                def fail(*unused):
                    C.set_last_error(5)
                    return 0 if operation=='AssignProcessToJobObject' else 0xffffffff
                setattr(api,operation,fail)
                with patch.dict(globals(),{'_Win':lambda:api}):
                    with self.assertRaises(RunnerError):
                        self.child("from pathlib import Path;Path('should-not-run').write_text('bad')")
                self.assertFalse((self.root/'should-not-run').exists())
        def test_descendant_nonzero_fails_even_after_root_success(self):
            source="import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(.25);raise SystemExit(7)'])"
            result=self.child(source)
            self.assertFalse(result.succeeded,result.summary())
            self.assertIn(7,result.process_exit_codes)
            self.assertGreaterEqual(result.process_count,2)
            self.assertTrue(result.process_accounting_complete)
            self.assertEqual(result.termination_reason,'descendant_nonzero_exit')
        def test_repeated_runs_do_not_accumulate_kernel_handles(self):
            import gc
            api=_Win()
            current=api.k.GetCurrentProcess
            current.restype=HANDLE;current.argtypes=[]
            count=api.k.GetProcessHandleCount
            count.restype=BOOL;count.argtypes=[HANDLE,C.POINTER(DWORD)]
            def handles():
                value=DWORD();api.check(count(current(),C.byref(value)),'GetProcessHandleCount')
                return value.value
            before=handles()
            for _ in range(3):self.assertTrue(self.child('pass').succeeded)
            gc.collect()
            self.assertLessEqual(handles(),before+2)
        def test_preset_cancellation_does_not_launch_or_create_logs(self):
            event=threading.Event();event.set()
            with self.assertRaisesRegex(RunnerError,'before launch'):
                self.child("from pathlib import Path;Path('should-not-run').write_text('bad')",cancel_event=event)
            self.assertEqual(list(self.root.iterdir()),[])
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    if not result.wasSuccessful():raise SystemExit(1)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test',action='store_true',required=True)
    parser.parse_args()
    _self_test()
