# NIC Simulator (HW6)

This repository contains the NIC simulator coursework implementation.
Only files in the "files for submission" section should be modified:
`L2.h/.cpp`, `L3.h/.cpp`, `L4.h/.cpp`, `NIC_sim.h/.cpp`, and `Makefile`.

## Build
```bash
make
./nic_sim.exe <params.txt> <packets.txt>
```

## Notes
- Output order: **RQ**, **TQ**, then **LOCAL DRAM**.
- L2 validates: dest MAC == NIC MAC and L2 checksum (sum of MAC bytes + L3 fields excluding L3 checksum).
- L3 validates: checksum; decrements TTL and routes to RQ/TQ or writes to local DRAM if dst == NIC IP.
- L4 writes into 64-byte per-connection buffer if (src,dst) is open and address bounds are valid.
