# Runpod H100 SXM

Choose **one H100 SXM 80 GB** on a Secure Cloud on-demand Pod. Runpod lists
**US$4.39 per GPU-hour**, before storage. The listed configuration has
125 GB host RAM and 20 vCPUs. Select a datacenter with both the GPU and the
network storage you will use. [Runpod pricing](https://www.runpod.io/pricing)

- Use an Ubuntu 24.04 CUDA 12.8.1 development template. Runpod documents
  `runpod/pytorch:1.0.3-cu1281-torch291-ubuntu2404` as an image option.
  Check `nvcc --version` against the build pin.
- Enable full SSH over TCP port 22 for file transfer. Mount a 120 GB network
  volume at `/workspace`. Attach the same volume to compatible CPU staging
  compute first if available. [Runpod SSH](https://docs.runpod.io/pods/configuration/use-ssh) · [Storage](https://docs.runpod.io/pods/storage/types)
- Set a one-hour Pod auto-stop and keep the network volume through the
  checkpoint and report retrieval. [Runpod CLI](https://docs.runpod.io/runpodctl/reference/runpodctl-pod)

Follow the [shared staging and pilot instructions](README.md).
