Incoherent TLB
==============

A naive linux kernel module to count number of TLB misses encountered during program execution.
The key idea behind this module to take advantage of the fact that page table entries and TLB entries are incoherent in x86 [1].
The module is further extended to handle Page Table Isolation (PTI/KAISER) [2] used to mitigate Meltdown vulnerability.
Using the same idea module also provides functionality to count number of read-only, unused and written pages.

Usage
-----

* Patch your kernel with `fault_hook.patch`.
* `cd src && make`
* `sudo insmod memtrack.ko`
* This creates a device `/dev/memtrack` that can be used to communicate with the user process.
* The module has the following sysfs variables (can be found in `/sys/kernel/memtrack`):
    * `command`: `0` indicates count TLB misses without PTI. `1` indicates count TLB misses with PTI. `2` indicates count read-only, unused and write pages.
    * `tlb_misses`: Contains the total number of TLB misses till now.
    * `readwss`: Contains number of read-only pages till now.
    * `writewss`: Contains number of pages that were written till now.
    * `unused`: Contains number of unused pages till now.
* Further you can get the pages that resulted in most TLB misses by sending read command `TLBMISS_TOPPERS` (see `test/usertest.c`).

Credits
-------

This module was written as part of an assignment for (CS730A)[https://www.cse.iitk.ac.in/users/deba/cs730/]. Module's base was provided as part of the assignment.


References
----------

* [1] - BadgerTrap: A Tool to Instrument x86-64 TLB Misses, Gandhi et al.
* [2] - KASLR is Dead: Long Live KASLR, Gruss et al.
