# Program targeted for Occlum need to be built with the Occlum toolchain
CC := occlum-g++

BUILD_DIR := build
BIN := $(BUILD_DIR)/vole

C_SRCS := $(wildcard *.cpp)
C_OBJS := $(addprefix $(BUILD_DIR)/,$(C_SRCS:.cpp=.o))
C_FLAGS := -Wall -lcrypto
LINK_FLAGS := $(C_FLAGS)

ALL_BUILD_SUBDIRS := $(sort $(patsubst %/,%,$(dir $(BIN) $(C_OBJS))))

.PHONY: all test clean

all: $(BIN)

$(BIN) $(C_OBJS): $(ALL_BUILD_SUBDIRS)

$(BIN): $(C_OBJS)
	@$(CC) $(C_OBJS) -o $@ $(LINK_FLAGS)
	@echo "LINK => $@"

$(BUILD_DIR)/%.o: %.cpp
	@$(CC) $(C_FLAGS) -c $< -o $@
	@echo "CC <= $@"

$(ALL_BUILD_SUBDIRS):
	@mkdir -p $@

clean:
	@-$(RM) -rf $(BUILD_DIR)
