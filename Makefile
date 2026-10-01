# m1_grin_miner_fastest: standalone live Grin Cuckatoo-32 miner (M1 Ultra / Apple Metal).
# Fast configuration: research instrumentation (kappa receipts) compiled out.
# Self-contained: src/ + submit_source/ + scheduler/. System Apple clang only.
#
#   make            # live miner + range harness + scheduler + strat_probe (into bin/)
#   make analyze    # clang static analyzer over all C/ObjC sources (gate: 0 findings)
#   make kernel-sync-check   # verify src/mine34_kernels.metal == kSrc embedded in mine34_live.m
#   make clean

CC    ?= xcrun clang
ROOT  := $(CURDIR)
BUILD := $(ROOT)/.build
SRC   := $(ROOT)/src
SUB   := $(ROOT)/submit_source
BIN   := $(ROOT)/bin

# m1rsi_core.c ships without its own #includes, so force-include std headers + the rsi header.
CORE_INCLUDES := -include stdint.h -include stddef.h -include string.h \
                 -include stdio.h -include stdlib.h -include m1ultra_grin_rsi.h

SDKROOT    := $(shell xcrun --show-sdk-path)
CFLAGS_SUB := -O3 -mcpu=apple-m1 -isysroot $(SDKROOT) -I$(SUB)
OBJCFLAGS  := -fobjc-arc -O3 -mcpu=apple-m1 -isysroot $(SDKROOT) -I$(SUB)
FRAMEWORKS := -framework Metal -framework Foundation

LIVE      := $(BIN)/mine34_live
HARNESS   := $(BIN)/mine34_range_harness
SCHEDULER := $(BIN)/m1_scheduler
PROBE     := $(BIN)/strat_probe

.PHONY: all clean analyze kernel-sync-check kernel-sync-write
all: $(LIVE) $(HARNESS) $(SCHEDULER) $(PROBE)

$(BUILD) $(BIN):
	mkdir -p $@

$(BUILD)/core.o: $(SUB)/m1rsi_core.c $(SUB)/m1ultra_grin_rsi.h | $(BUILD)
	$(CC) $(CFLAGS_SUB) $(CORE_INCLUDES) -c $< -o $@

$(BUILD)/job_assigner.o: $(SUB)/m1mean_sidecar_job_assigner.c $(SUB)/m1mean_sidecar_job_assigner.h | $(BUILD)
	$(CC) $(CFLAGS_SUB) -c $< -o $@

$(BUILD)/submit.o: $(SUB)/m1mean_sidecar_submit.c $(SUB)/m1mean_sidecar_submit.h | $(BUILD)
	$(CC) $(CFLAGS_SUB) -c $< -o $@

$(LIVE): $(SRC)/mine34_live.m $(BUILD)/job_assigner.o $(BUILD)/submit.o $(BUILD)/core.o | $(BIN)
	$(CC) $(OBJCFLAGS) $(FRAMEWORKS) $^ -lpthread -o $@

$(HARNESS): $(SRC)/mine34_range_harness.m $(SRC)/mine34_live.m $(BUILD)/job_assigner.o $(BUILD)/submit.o $(BUILD)/core.o | $(BIN)
	$(CC) $(OBJCFLAGS) $(FRAMEWORKS) $(SRC)/mine34_range_harness.m $(BUILD)/job_assigner.o $(BUILD)/submit.o $(BUILD)/core.o -lpthread -o $@

$(SCHEDULER): $(ROOT)/scheduler/m1_scheduler.c | $(BIN)
	$(CC) -O2 -mcpu=apple-m1 -isysroot $(SDKROOT) $< -lpthread -o $@

$(PROBE): $(ROOT)/debug/strat_probe.c $(BUILD)/job_assigner.o | $(BIN)
	$(CC) -O2 -isysroot $(SDKROOT) -I$(SUB) $< $(BUILD)/job_assigner.o -o $@

# Static-analyzer gate: every source, 0 findings required before a live run.
analyze:
	$(CC) --analyze -Xclang -analyzer-output=text $(CFLAGS_SUB) $(CORE_INCLUDES) $(SUB)/m1rsi_core.c -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text $(CFLAGS_SUB) $(SUB)/m1mean_sidecar_job_assigner.c -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text $(CFLAGS_SUB) $(SUB)/m1mean_sidecar_submit.c -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text $(OBJCFLAGS) $(SRC)/mine34_live.m -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text $(OBJCFLAGS) -DRANGE_HARNESS_ANALYZE $(SRC)/mine34_range_harness.m -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text -O2 -isysroot $(SDKROOT) $(ROOT)/scheduler/m1_scheduler.c -o /dev/null
	$(CC) --analyze -Xclang -analyzer-output=text -O2 -isysroot $(SDKROOT) -I$(SUB) $(ROOT)/debug/strat_probe.c -o /dev/null
	@echo "analyze: done (any findings printed above)"

# single-source-of-truth: src/mine34_kernels.metal is GENERATED from the kSrc
# NSString in src/mine34_live.m (the source the miner actually compiles).
kernel-sync-check:
	python3 $(ROOT)/tools/kernel_sync_check.py

kernel-sync-write:
	python3 $(ROOT)/tools/kernel_sync_check.py --write

clean:
	rm -rf $(BUILD) $(LIVE) $(HARNESS) $(SCHEDULER) $(PROBE)
