# Initial Report

## Team

We are Team Bawang, consisting of Michael Loipführer and Julien Schmidt.
As the name already indicates, we are going to implement an onion routing module.

Both team members have successfully completed the courses "Introduction to Programming" and GRNVS, which we believe is enough experience to complete this project, as those are excellent courses.
We might have further relevant experience from our work at StuStaNet e. V., open source projects and other courses in the field of IT security and computer networks, also including network applications in Go.

## Implementation

As the programming language, we have chosen Go 1.14, as it comes with most batteries included for network programming and offers good performance while also taking care of memory management and provides type-safety. Go also provides excellent native support for concurrency in the form of so-called goroutines (green threads), which make it unnecessary to e.g. set up an event loop (and making sure that nothing blocks it) and tracking the state for async execution.

Go further allows us to easily support (almost) all platforms supported by the Go toolchain (`$ go tool dist list`), however we are only going to test on Linux and macOS, as those are our development platforms.
We are also going to rely mostly on the standard Go toolchain as our build system, as there is little reason to use anything more complicated.


## Software Quality Guarantee Measures

To ensure the excellent quality of our software, we are going to use Go unit tests (`go test`), using e.g. mocking and table-driven tests. We intend to use the [Testify framework](https://github.com/stretchr/testify) to make writing tests a little less cumbersome.

We are further planning to set up continuous integration in Gitlab, including an integration test with the [`voidphone_testing`](https://gitlab.lrz.de/netintum/teaching/voidphone_testing) dummy implementation, as well as code analysis with `gofmt` (code formatting) and [`golangci-lint`](https://github.com/golangci/golangci-lint), which is a meta linter allowing us to easily test against many Go linters and static code analyzers.


## Workflow

We intend to work in close collaboration on the implementation and do not intend to make a clear separation of responsibilities, as we are both eager to work on all parts of the project and want to review each other's code. We will coordinate with each other to work on different details of the implementation at a time.
As we are also only two people working on the code, we **do not** intend to use a branch-based git workflow. Instead we plan to follow a flat-history approach, where will rebase our local clone often on the `origin/master`, which is also when we will **review any intermediate changes**. As we intend to mostly work on the project at the same time and while being at the same location, coordination and feedback is easily possible via verbal communication.
The `origin/master` should not be broken at any time. If the CI has any complaints, those should be addressed immediately (except for yet unimplemented features).


## License

We chose the MIT license because we believe in free software and e.g. GPLv2/v3 is definitely not free.
MIT is a minimal license which does not restrict any usage of our software while also limiting our liability.


## Third-Party Libraries

* github.com/go-ini/ini (reading INI files)
* github.com/stretchr/testify (testing framework)
* golang.org/x/crypto (additional crypto utils)
* golang.org/x/net (additional network utils)
