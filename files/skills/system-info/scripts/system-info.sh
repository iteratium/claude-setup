#!/usr/bin/env bash
# Prints host OS/CPU/memory/GPU details as "key: value" lines (Linux, macOS).
# Always exits 0: a non-zero exit would abort the skill that injects this output.

have() { command -v "$1" >/dev/null 2>&1; }
line() { printf '%s: %s\n' "$1" "${2:-unknown}"; }

linux() {
  local os gpus card vram drv
  os=$( . /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$NAME $VERSION_ID}")
  line "OS" "$os"
  line "Kernel" "$(uname -r)"
  line "Arch" "$(uname -m)"

  if have lscpu; then
    local model sockets cores threads maxmhz
    model=$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)
    sockets=$(lscpu | sed -n 's/^Socket(s):[[:space:]]*//p' | head -1)
    cores=$(lscpu | sed -n 's/^Core(s) per socket:[[:space:]]*//p' | head -1)
    threads=$(nproc 2>/dev/null)
    maxmhz=$(lscpu | sed -n 's/^CPU max MHz:[[:space:]]*//p' | head -1)
    line "CPU" "$model"
    line "CPU cores/threads" "$(( ${sockets:-1} * ${cores:-0} )) cores / ${threads} threads"
    [[ -n $maxmhz ]] && line "CPU max clock" "${maxmhz%.*} MHz"
  else
    line "CPU" "$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1)"
  fi

  line "RAM" "$(awk '/^MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo)"

  if have lspci; then
    gpus=$(lspci 2>/dev/null | grep -Ei 'vga|3d|display' | sed 's/^[^ ]* [^:]*: //')
  fi
  if [[ -n $gpus ]]; then
    while IFS= read -r g; do line "GPU" "$g"; done <<<"$gpus"
  else
    line "GPU" "none detected"
  fi
  if have nvidia-smi; then
    nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader 2>/dev/null |
      while IFS=, read -r n m d; do line "NVIDIA GPU" "$n,$m, driver$d"; done
  fi
  for card in /sys/class/drm/card[0-9]*/device; do
    [[ -e $card && $(basename "$(dirname "$card")") =~ ^card[0-9]+$ ]] || continue
    drv=$(basename "$(readlink -f "$card/driver" 2>/dev/null)" 2>/dev/null)
    vram=""
    [[ -r $card/mem_info_vram_total ]] &&
      vram=$(awk '{printf "%.1f GiB", $1/1073741824}' "$card/mem_info_vram_total")
    line "GPU driver ($(basename "$(dirname "$card")"))" "${drv:-unknown}${vram:+, VRAM $vram}"
  done
}

macos() {
  line "OS" "$(sw_vers -productName) $(sw_vers -productVersion)"
  line "Kernel" "$(uname -r)"
  line "Arch" "$(uname -m)"
  line "CPU" "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
  line "CPU cores/threads" "$(sysctl -n hw.physicalcpu) cores / $(sysctl -n hw.logicalcpu) threads"
  line "RAM" "$(sysctl -n hw.memsize | awk '{printf "%.1f GiB", $1/1073741824}')"
  system_profiler SPDisplaysDataType 2>/dev/null |
    awk -F': ' '/Chipset Model/ {print "GPU: " $2} /VRAM/ {print "GPU VRAM: " $2} /Metal/ {print "GPU Metal: " $2}'
}

case $(uname -s) in
  Linux) linux ;;
  Darwin) macos ;;
  *) line "OS" "$(uname -srm)" ;;
esac
exit 0
