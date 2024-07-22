dyno
====

The goal of this package is to take an experimental pass at refactoring `net/http` to be effectively single connection.

The motivation is to reduce tail latency, and allow garbage collection and other steps to be taken _after_ the response is written back to the client.

The motivation is _not_ aggregate throughput.