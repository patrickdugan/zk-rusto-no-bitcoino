# Hyperstack H100 SXM

Check stock for **H100-80G-SXM5** in the console. The public price is
**US$3.20 per GPU-hour**. The public flavor catalog lists
`n3-H100-SXM5x8` in Canada and the US. That configuration rents eight
GPUs, so check the displayed GPU count and total hourly rate against the
budget for a one-GPU pilot. The account pricebook is the source for any
applicable discount. [Hyperstack pricing](https://www.hyperstack.cloud/gpu-pricing) · [Flavors](https://docs.hyperstack.cloud/docs/hardware/flavors/) · [Account pricebook](https://docs.hyperstack.cloud/docs/billing/pricebook/)

- Use Ubuntu 24.04 with the R570/CUDA 12.8 image and verify the CUDA
  12.8.1 development toolkit on build compute. Add your SSH public key.
- Attach a persistent volume with at least 120 GB at `/workspace`.
  Build and stage on compatible CPU compute first when available. Transfer
  the volume to the GPU VM in the same region.
- After the timed run, preserve the volume or retrieve the results through
  SSH before ending the GPU rental.

Follow the [shared staging and pilot instructions](README.md). The common
runner measures one GPU. Select a single-GPU SXM VM when available for a
like-for-like pilot and check the stock again before committing funds.
