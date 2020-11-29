# Copyright (C) 2020-2021,  0xN3utr0n

# Kanis is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Kanis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Kanis. If not, see <http://www.gnu.org/licenses/>.

BINPATH         ?= $(PWD)/bin
BINTEST         ?= $(BINPATH)/threats.test
TEST_SAMPLES    ?= $(PWD)/Tests
GO              ?= go
USER_ID         ?= $(shell id -u)
PACKAGES        ?= rulengine logger ftrace
PREFIX          ?= /var/kanis

all: build

build:
	@GOBIN=$(BINPATH) go install .

build_with_race_detector:
	@GOBIN=$(BINPATH) go install -race .

build_test:
	@cd $(TEST_SAMPLES) && $(MAKE) all
	@go test -o $(BINTEST) -tags integration -c rulengine/threat/threats_test.go

install:
	@mkdir -p $(PREFIX)/files $(PREFIX)/rules

clean: clean_test
	@rm -rf $(BINPATH)/*

clean_test:
	@cd $(TEST_SAMPLES) && $(MAKE) clean

test:
ifeq ($(USER_ID), 0)
	@PATH=$(BINPATH):$(PATH) $(BINTEST) -test.v
else
	$(error Run tests with root. Try 'sudo -s make test')
endif
	
fmt:
	@$(GO)fmt -l -s -w $(PACKAGES)
