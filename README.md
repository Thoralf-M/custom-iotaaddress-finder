# custom-iotaaddress-finder

Find a seed or private key to an address with a word at the beginning.

For example if you search for an address with `TROLL` it will search for an address like `TROLL9TVCHOCOKBNWILZKMV9EKFPFBJLODURQZFSATK9RWJBUJOTTTBXJDPLPEDBLCKOVJGWFKWJYLZYDDYLTRBFNW` and returns the seed/private key to it.

If only the private key is to be returned it is almost twice as fast, but you don't get a seed which you can use in Trinity.



Works with `rustup default nightly-2019-04-30`

`git clone https://github.com/Thoralf-M/custom-iotaaddress-finder`

`cd custom-iotaaddress-finder`

`cargo build --release`

`target\release\custom-iotaaddress-finder.exe`
