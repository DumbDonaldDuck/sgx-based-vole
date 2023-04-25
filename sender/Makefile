CC := g++
CFLAGS := -lcrypto

BUILD_DIR := build
BIN := $(BUILD_DIR)/sender

C_SRCS := $(sort $(wildcard *.cpp))
C_OBJS := $(addprefix $(BUILD_DIR)/,$(C_SRCS:.cpp=.o))

ALL_BUILD_SUBDIRS := $(sort $(patsubst %/,%,$(dir $(BIN) $(C_OBJS))))

.PHONY: all clean

all: $(BIN)

$(BIN) $(C_OBJS): $(ALL_BUILD_SUBDIRS)

$(BIN): $(C_OBJS)
	@$(CC) $(C_OBJS) -o $@ $(CFLAGS)
	@echo "LINK => $@"

$(BUILD_DIR)/%.o: %.cpp
	@$(CC) $(C_FLAGS) -c $< -o $@
	@echo "CC <= $@"

$(ALL_BUILD_SUBDIRS):
	@mkdir -p $@

clean:
	@-$(RM) -rf $(BUILD_DIR)