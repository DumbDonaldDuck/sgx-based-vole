SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW

.PHONY: all build_src test clean

all: occlum_instance

# occlum_instance: build_src
# 	@mkdir -p occlum_instance
# 	@cd occlum_instance && \
# 		occlum init && \
# 		rm -rf image && \
# 		rm -r Occlum.json && \
# 		cp ../occlum_default.json . && \
# 		mv occlum_default.json Occlum.json && \
# 		copy_bom -f ../receiver.yaml --root image --include-dir /opt/occlum/etc/template && \
# 		occlum build

occlum_instance: build_src
	bash occlum_build.sh

build_src:
	@$(MAKE) --no-print-directory -C in-sgx-receiver
	@$(MAKE) --no-print-directory -C out-sgx-receiver
	@$(MAKE) --no-print-directory -C sender

PROTOCOL_MODE=0
# =0	A/C are not needed to encrypt
# =1	A/C are needed to encrypt
test:
	@LD_LIBRARY_PATH=out-sgx-receiver/build:$(SGX_SDK)/sdk_libs RUST_BACKTRACE=1 \
		out-sgx-receiver/build/receiver $(PROTOCOL_MODE)
	

clean:
	@$(MAKE) --no-print-directory -C in-sgx-receiver clean
	@$(MAKE) --no-print-directory -C out-sgx-receiver clean
	@$(MAKE) --no-print-directory -C sender clean
	@rm -rf .occlum occlum_instance
