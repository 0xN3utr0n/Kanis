CC=gcc

.PHONY: all sample2 sample3 sample4 sample5 sample6

all: sample2 sample3 sample4 sample5 sample6

sample2:
	@mkdir $@ &>/dev/null
	@cp /usr/bin/sleep $@/$@.bin
	@upx -9 $@/$@.bin 1>/dev/null

sample3: sample3/sample3.c
	@$(CC) -o $@/$@.bin $^

sample4: sample4/sample4.c
	@$(CC) -o $@/$@.bin $^

sample5: sample5/sample5.c
	@$(CC) -static -o $@/$@.bin $^
	@upx -9 $@/$@.bin 1>/dev/null

sample6: sample6/sample6.c
	@$(CC) -o $@/$@.bin $^

clean:
	@find . -type f -name "*.bin" -delete 