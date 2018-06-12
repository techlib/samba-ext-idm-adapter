#!/usr/bin/make -f

test: run-tests
run-tests:
	@test/run

clean: clean-tests
clean-tests:
	@rm -rf test/mock

# EOF
