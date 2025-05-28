KERNEL_SRC ?= /usr/src/linux-6.1.140

obj-$(CONFIG_CRYPTOTUN) += cryptotun.o
cryptotun-objs := main.o crypto.o device.o netlink.o receive.o replay.o transmit.o

obj-$(CONFIG_CRYPTOTUN_TEST) += replay_test.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) CONFIG_CRYPTOTUN=m modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) CONFIG_CRYPTOTUN=m clean
	@if [ -L "$(KERNEL_SRC)/drivers/net/cryptotun" ]; then \
		rm "$(KERNEL_SRC)/drivers/net/cryptotun"; \
	fi
	@if grep -q 'cryptotun/Kconfig' "$(KERNEL_SRC)/drivers/net/Kconfig"; then \
		sed -i '/cryptotun\/Kconfig/d' "$(KERNEL_SRC)/drivers/net/Kconfig"; \
	fi
	@if grep -q 'CONFIG_CRYPTOTUN' "$(KERNEL_SRC)/drivers/net/Makefile"; then \
		sed -i '/CONFIG_CRYPTOTUN/d' "$(KERNEL_SRC)/drivers/net/Makefile"; \
	fi

.PHONY: format
format:
	clang-format -i *.[ch]

.PHONY: test
test:
	@if [ ! -L "$(KERNEL_SRC)/drivers/net/cryptotun" ]; then \
		ln -s "$(PWD)" "$(KERNEL_SRC)/drivers/net/cryptotun"; \
	fi
	@if ! grep -q 'CONFIG_CRYPTOTUN' "$(KERNEL_SRC)/drivers/net/Makefile"; then \
		echo 'obj-$$(CONFIG_CRYPTOTUN) += cryptotun/' >> "$(KERNEL_SRC)/drivers/net/Makefile"; \
	fi
	@if ! grep -q 'cryptotun' "$(KERNEL_SRC)/drivers/net/Kconfig"; then \
		echo 'source "drivers/net/cryptotun/Kconfig"' >> "$(KERNEL_SRC)/drivers/net/Kconfig"; \
	fi
	$(KERNEL_SRC)/tools/testing/kunit/kunit.py run --kunitconfig="$(PWD)/.kunitconfig"