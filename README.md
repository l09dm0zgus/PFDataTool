##  PFDataTool
Custom archiver with supporting LZ4 compression and AES256 encryption.Written in C++17.
###  Installing
Downloaad meson and execute :
` cd PFDataTool && meson build && meson compile -C build `
Additional dependencies not needed.'
### Usage
Just pack folder to archive :
`./PFDataTool --create arhive.pfd --add folder1`
With compression :
`./PFDataTool --create archive.pfd --add folder1 --compression 1`
With encryption :
`./PFDataTool --create archive.pfd --add folder 1 --encryption 1 --password 123`
With encryption and compression :
`./PFDataTool --create archive.pfd --add folder1 --compression 1 --encryption 1 --password 123`
Extract archive:
``./PFDataTool --extract archive.pfd folder2`
Extract encrypted archive
`./PFDataTool --extract archive.pfd folder2 --password 123`

