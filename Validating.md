# Testing the extracted modules

## Compilation
cd into the extracted folder and run the Makefile.

## Loading
To check if the extracted code successfully loads at the appropriate hookpoint, use the `verify_extraction.py` script.

```
usage: verify_extraction.py [-h] [-t BPFTCPROGFILE] [-x BPFXDPPROGFILE] [-u TCSEC] [-y XDPSEC]

eBPF Extraction Verifier

options:
  -h, --help            show this help message and exit
  -t BPFTCPROGFILE, --bpfTCProgFile BPFTCPROGFILE
                        eBPF Object file for TC hook point
  -x BPFXDPPROGFILE, --bpfXDPProgFile BPFXDPPROGFILE
                        eBPF Object file for XDP hook point
  -u TCSEC, --TCSec TCSEC
                        TC code section name
  -y XDPSEC, --XDPSec XDPSEC
                        XDP code section name

```

For instance, to verify the loading of xdpdecap section in extracted.o at the XDP hook point, use the following command

```
verify_extraction.py  -x extracted.o -y xdp_decap

```
Check if the ebpf code is successfully attached to the appropriate hookpoint using

```
bpftool net
```

## Validating the correctness of extracted Code using synthetic traffic generation
