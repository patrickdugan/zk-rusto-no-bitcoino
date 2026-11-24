//! Direct gate-to-BQS lowering, independent of garbling. PNS-04A.
//! Wires are compiled from the pinned BitVM3 Nova kernels. A BQS relation
//! includes bitness of every unknown and w0=1. No host acceptance bit is used.
use garbled_snark_verifier::{
    CircuitContext, Gate, GateType, WireId,
    circuit::{ExecuteMode, FromWires, WiresObject},
};
use sha2::{Digest,Sha256};
use std::io::{self,Write};

/// BQS row: A*w[a]*w[b] = w[z] - B*w[a] - C*w[b] - D*w[0].
/// w[0]=1; w[1]=0; wire IDs 0 and 1 are swapped. All variables are Boolean.
#[derive(Clone,Copy,Debug)]
pub struct Row { pub a:u32,pub b:u32,pub z:u32,pub d:i8,pub l:i8,pub r:i8,pub m:i8 }
impl Row {
    pub fn gate(g:&Gate)->Self {
        let f=g.gate_type.f();
        let d=i8::from(f(false,false));
        let l=i8::from(f(true,false))-d;
        let r=i8::from(f(false,true))-d;
        let m=i8::from(f(true,true))-d-l-r;
        Self{a:slot(g.wire_a),b:slot(g.wire_b),z:slot(g.wire_c),d,l,r,m}
    }
    pub fn pin(z:u32,v:bool)->Self{Self{a:0,b:0,z,d:i8::from(v),l:0,r:0,m:0}}
    pub fn value(&self,w:&[u8])->i16 {
        let x=w[self.a as usize] as i16;let y=w[self.b as usize] as i16;
        self.d as i16*w[0] as i16+self.l as i16*x+self.r as i16*y+self.m as i16*x*y
    }
    pub fn passes(&self,w:&[u8])->bool{self.value(w)==w[self.z as usize] as i16}
    pub fn bytes(&self)->[u8;16]{
        let mut s=[0;16];s[..4].copy_from_slice(&self.a.to_le_bytes());
        s[4..8].copy_from_slice(&self.b.to_le_bytes());s[8..12].copy_from_slice(&self.z.to_le_bytes());
        s[12..].copy_from_slice(&[self.d as u8,self.l as u8,self.r as u8,self.m as u8]);s
    }
}
fn slot(w:WireId)->u32{
    u32::try_from(match w.0 {0=>1,1=>0,n=>n}).expect("BQS index fits u32")
}
/// One global namespace, no component/template memoization. Each instance is
/// expanded; every gate, including XOR, is counted. Trace generation uses
/// the original GateType truth function; the independent row checker uses
/// integer polynomial residuals (absolute residual <= 8 < BN254 Fr modulus).
pub struct Compiler {
    pub rows:Vec<Row>, pub assignment:Vec<u8>,
    defined:Vec<bool>, inputs:Vec<u32>, pub pins:Vec<Row>,
    pub gate_counts:[u64;11],
}
impl Compiler {
    pub fn new()->Self{
        Self{rows:vec![],assignment:vec![1,0],defined:vec![true,true],inputs:vec![],
            pins:vec![Row::pin(1,false)],gate_counts:[0;11]}
    }
    pub fn inputs(&self)->&[u32]{&self.inputs}
    pub fn input(&mut self,b:bool)->WireId{
        let w=self.issue_wire();let i=slot(w) as usize;
        self.defined[i]=true;self.assignment[i]=u8::from(b);self.inputs.push(i as u32);w
    }
    pub fn word(&mut self,b:&[u8])->[WireId;256]{
        assert_eq!(b.len(),32);
        std::array::from_fn(|i|self.input((b[i/8]>>(i%8))&1!=0))
    }
    pub fn pin(&mut self,w:WireId,b:bool){
        assert!(self.defined[slot(w) as usize]);self.pins.push(Row::pin(slot(w),b));
    }
    pub fn accept(&mut self,w:WireId){self.pin(w,true)}
    pub fn seal(&self){
        assert!(self.defined.iter().all(|x|*x),"unassigned wire");
        assert!(self.rows.len()+self.inputs.len()+2==self.assignment.len(),"single definitions");
    }
    pub fn check(&self,w:&[u8])->bool{
        w.len()==self.assignment.len()&&w[0]==1&&w.iter().all(|x|*x<=1)&&
        self.rows.iter().chain(&self.pins).all(|r|r.passes(w))
    }
    /// Re-evaluate the equations for a new input assignment. This is not
    /// verifier acceptance; all public pins and the accept pin are checked
    /// separately. Output gate order was validated by add_gate.
    pub fn evaluate(&self,bits:&[u8])->Vec<u8>{
        assert_eq!(bits.len(),self.inputs.len());assert!(bits.iter().all(|&x|x<=1));
        let mut a=vec![0;self.assignment.len()];a[0]=1;
        for (i,b) in self.inputs.iter().zip(bits){a[*i as usize]=*b;}
        for r in &self.rows{let v=r.value(&a);assert!((0..=1).contains(&v));a[r.z as usize]=v as u8;}
        a
    }
    pub fn digest(&self)->String{
        let mut h=Sha256::new();h.update(b"PNS-BQS-GATES/v1\0");
        for n in [self.assignment.len(),self.inputs.len(),self.rows.len(),self.pins.len()]{h.update((n as u64).to_le_bytes());}
        for i in &self.inputs{h.update(i.to_le_bytes());}
        for r in self.rows.iter().chain(&self.pins){h.update(r.bytes());}
        hex::encode(h.finalize())
    }
    pub fn export(&self,out:impl AsRef<std::path::Path>)->io::Result<()>{
        use std::{fs,io::BufWriter};
        let out=out.as_ref();fs::create_dir_all(out)?;
        let mut r=BufWriter::new(fs::File::create(out.join("rows.bin"))?);
        for row in self.rows.iter().chain(&self.pins){r.write_all(&row.bytes())?;}r.flush()?;
        fs::write(out.join("assignment.bin"),&self.assignment)?;
        let meta=serde_json::json!({"format":"PNS-BQS-GATES/v1","w0":1,"w1":0,
          "boolean_unknowns":self.assignment.len()-1,"input_slots":self.inputs,
          "gate_rows":self.rows.len(),"pin_rows":self.pins.len(),"shape_sha256":self.digest()});
        fs::write(out.join("manifest.json"),serde_json::to_vec_pretty(&meta)?)?;
        Ok(())
    }
    pub fn stats(&self)->serde_json::Value{
        self.seal();
        let quadr=self.rows.iter().chain(&self.pins).filter(|r|r.m!=0).count();
        let n=self.assignment.len()-1;
        serde_json::json!({"boolean_unknowns":n,"inputs":self.inputs.len(),
            "gate_rows":self.rows.len(),"pin_rows":self.pins.len(),
            "bqs_equations_excluding_implicit_bitness":self.rows.len()+self.pins.len(),
            "quadratic_equations":quadr,"linear_equations":self.rows.len()+self.pins.len()-quadr,
            "max_products_per_equation":usize::from(quadr>0),
            "garbling_free_gate_count":self.gate_counts[8..].iter().sum::<u64>(),
            "gate_counts":self.gate_counts,"row_bytes":16*(self.rows.len()+self.pins.len()),
            "shape_sha256":self.digest()})
    }
}
impl CircuitContext for Compiler {
    type Mode=ExecuteMode;
    fn issue_wire(&mut self)->WireId{
        let w=WireId(self.assignment.len());self.assignment.push(0);self.defined.push(false);w
    }
    fn add_gate(&mut self,g:Gate){
        let r=Row::gate(&g);let a=r.a as usize;let b=r.b as usize;let z=r.z as usize;
        assert!(z>=2&&z<self.defined.len()&&!self.defined[z],"gate output not fresh");
        assert!(self.defined[a]&&self.defined[b],"gate input not defined");
        self.assignment[z]=u8::from(g.gate_type.f()(self.assignment[a]==1,self.assignment[b]==1));
        self.defined[z]=true;self.gate_counts[g.gate_type as usize]+=1;
        self.rows.push(r);
    }
    fn with_named_child<I:WiresObject,O:FromWires>(
        &mut self,_key:[u8;8],inputs:I,f:impl Fn(&mut Self,&I)->O,arity:usize
    )->O{
        // Expand the component in the same namespace; its outputs may be
        // aliases (including constants), so never allocate dummy output wires.
        let out=f(self,&inputs);let w=out.to_wires_vec();assert_eq!(w.len(),arity);
        assert!(w.iter().all(|x|self.defined[slot(*x) as usize]));out
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn all_gate_truth_tables_and_invalid_outputs(){
        for g in [GateType::And,GateType::Nand,GateType::Nimp,GateType::Imp,GateType::Ncimp,
          GateType::Cimp,GateType::Nor,GateType::Or,GateType::Xor,GateType::Xnor,GateType::Not]{
            for a in [false,true]{for b in [false,true]{
                let mut c=Compiler::new();let x=c.input(a);let y=c.input(b);let z=c.issue_wire();
                c.add_gate(Gate::new(g,x,y,z));c.accept(z);c.seal();
                assert_eq!(c.check(&c.assignment),g.f()(a,b));
                assert!(c.rows[0].passes(&c.assignment));
                let mut bad=c.assignment.clone();bad[z.0]^=1;assert!(!c.check(&bad));
                let mut bad=c.assignment.clone();bad[x.0]=2;assert!(!c.check(&bad));
            }}
        }
    }
    #[test]fn constant_mapping_and_output_pin(){
        let mut c=Compiler::new();let x=c.input(false);let z=c.issue_wire();
        c.add_gate(Gate::xor(WireId(1),x,z));c.accept(z);c.seal();
        assert!(c.check(&c.assignment));assert!(!c.check(&c.evaluate(&[1])));
        let mut bad=c.assignment.clone();bad[1]=1;assert!(!c.check(&bad));
        let mut bad=c.assignment.clone();bad[0]=0;assert!(!c.check(&bad));
    }
}
