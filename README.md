# Analyzing initcall

Boot time is always important in any embedded systems. One of the ways to analyze and improve boot time is by examining initcall execution and probe times. I learned about the following tools during a [Boot-Time SIG](https://elinux.org/Boot-Time_SIG) meeting:

- [**grab-boot-data.sh**](https://birdcloud.org/boot-time/Boot-time_Tools) - collects data reading dmesg and /proc/config.gz
- [**analyze-initcall-debug.py**](https://lore.kernel.org/linux-embedded/2289257.vFx2qVVIhK@fedora.fritz.box/T/#t) - analyze the collected data and generate html/text summary

## Experiment Setup

To evaluate boot process, I analyzed four development boards:

- **BeagleBone Black**
- **BeagleBone White**
- **i.MX6 SoloX Sabre**
- **MicroZed**

### Steps Followed:

1. **Created a minimal image** using Linux version **6.13.9** with `multi_v7_defconfig`. The same `zImage` was used across all boards.
2. **Set the kernel command line options**: `quiet initcall_debug log_buf_len=10M`.
3. **Booted the device**, waited a few seconds, and ran:
   ```sh
   grab-boot-data.sh -l <user_name> -m board_name
   ```
4. **Captured the output** via serial console, since my minimal system had no network support.
5. **Analyzed the data** using:
   ```sh
   cat <genrated_file> | python3 analyze-initcall-debug.py
   ```
6. **Optional:** You can upload using following in the birdcloud.org
   ```sh
   grab-boot-data.sh -u <file>
   ```

## Boot Time Analysis

There were 1542 initcalls in each platfrom. The logs files are in this [link](https://birdcloud.org/boot-time/Boot_Data_Set_Summary?action=BootRegion.machine_list_by_lab&lab=manish_labs)

### BeagleBone Black

- **Total boot time:** 2423ms
- **Top Initcall Delay:** `deferred_probe_initcall` → **1388ms**

### BeagleBone White

- **Total boot time:** 3440ms
- **Top Initcall Delay:** `deferred_probe_initcall` → **1732ms**

### i.MX6 SoloX Sabre

- **Total boot time:** 12665ms
- **Top Initcall Delay:** `trace_eval_sync` → **330ms**

### MicroZed

- **Total boot time:** 1528ms
- **Top Initcall Delay:** `trace_eval_sync` → **801ms**

## Conclusion

Overall I think this is one of tools in your bag pack to analyze initcalls. Instead of manually searching through log files, they offer a summarized view, making it easier to spot delays.

If you are looking to optimize boot time, these tools are a good starting point for understanding where delays occur.
