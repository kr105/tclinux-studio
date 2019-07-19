# tclinux-studio
Small tool to test, extract and create tclinux.bin firmware image files from MTK based devices. I have tested this successfully on multiple devices from multiple vendors.

This tool is very alpha, I plan to eventually make it a full featured tclinux.bin editor but right now it does the bare minimum.

Documentation will be improved at some point but for now here is a quick reference to what this little tool does.

## Usage

### Check file integrity

    ./tclstudio -t tclinux.bin
Checks tclinux.bin header validity and file integrity.

### Extract file

    ./tclstudio -e tclinux.bin kernel rootfs
Extract tclinux.bin into 'kernel' and 'rootfs' files.

### Create file

    ./tclstudio -c tclinux-new.bin -k kernel -r rootfs -da 0x80002000 -v FW_VERSION -dm DEVICE_MODEL
Creates a valid tclinux-new.bin from 'kernel' and 'rootfs' files. 0x80002000 indicates the decompress address for the kernel (get it from the -t option, it is important to use the right value or brick will happen), FW_VERSION the version of the firmware and DEVICE_MODEL the physical hardware device model.


**Note: I do not guarantee that this will work for your device, at the very least you should make sure that the original firmware file pass all checks on the -t option to discard your device using a customized variation of this format.**