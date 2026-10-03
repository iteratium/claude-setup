---
name: system-info
description: Host hardware and OS details (distro, kernel, CPU model/cores/threads/clock, RAM, GPU model, VRAM, driver). Use when a task depends on hardware or OS specifics, e.g. choosing build parallelism, CUDA/ROCm/driver issues, memory limits, or picking OS-specific packages.
---

Current host details:

!`bash ${CLAUDE_SKILL_DIR}/scripts/system-info.sh`

Values are live as of this invocation. Fields marked unknown or none detected weren't available on this system.
