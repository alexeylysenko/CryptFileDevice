CryptFileDevice
===============

Qt cross-platform class which allows transparently encrypt/decrypt QFileDevice using AES-CTR algorithm with OpenSSL library.

## Dependencies

| Name         | Version                          |
|--------------|----------------------------------|
| Qt           | >= 5.1.0                         |
| C++ compiler | supporting C++11 (i.e. gcc 4.6+) |

## Usage

Copy 2 files (cryptfiledevice.cpp and cryptfiledevice.h) into your Qt project. See `examples/` for examples on using this class.

In examples folder there are 2 example projects.

1) CryptFileDeviceExample - test general operations with file and compare results with QFile object.

2) WebViewWithCryptFileDevice - show how to display the user encrypt content (image).

## Contact

Questions and suggestions can be sent to email: lysenkoalexmail@gmail.com

## Contributing

Please report any suggestions, feature requests, bug reports, or annoyances to
the Github [issue tracker][issue_tracker]. 

## License

CrypFileDevice is licensed under [MIT](LICENSE).

## Thanks to

Special thanks to Ruslan Salikhov for testing and sensible suggestions.

Thanks to habrauser Disasm for suggestion.


[issue_tracker]: https://github.com/alexeylysenko/CryptFileDevice/issues