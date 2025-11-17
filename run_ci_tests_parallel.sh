#!/bin/bash
# Parallel CI Test Suite Runner
# Runs tests in parallel phases for faster execution

set -e  # Exit on first failure

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Track overall status
FAILED=0
START_TIME=$(date +%s)

# Temporary directory for logs
LOG_DIR=$(mktemp -d)
trap "rm -rf $LOG_DIR" EXIT

echo "═══════════════════════════════════════════════════════════════════════════"
echo "              RUST V-HSM CAN - PARALLEL CI TEST SUITE"
echo "═══════════════════════════════════════════════════════════════════════════"
echo ""
echo -e "${CYAN}Logs directory: $LOG_DIR${NC}"
echo ""

# Function to print section header
print_section() {
    echo -e "${BOLD}${BLUE}→ Phase $1: $2${NC}"
}

# Function to print test status with timing
print_status() {
    local name="$1"
    local duration="$2"
    local logfile="$3"

    if [ -f "$logfile" ] && grep -q "FAILED\|error\|Error" "$logfile"; then
        echo -e "  ${RED}✗ FAIL${NC}: $name (${duration}s)"
        FAILED=1
        return 1
    else
        echo -e "  ${GREEN}✓ PASS${NC}: $name (${duration}s)"
        return 0
    fi
}

# Function to run command with timing
run_timed() {
    local name="$1"
    local logfile="$2"
    shift 2

    local start=$(date +%s)
    if "$@" > "$logfile" 2>&1; then
        local end=$(date +%s)
        local duration=$((end - start))
        echo "$duration" > "${logfile}.time"
        return 0
    else
        local end=$(date +%s)
        local duration=$((end - start))
        echo "$duration" > "${logfile}.time"
        return 1
    fi
}

# Function to show spinner while waiting
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null 2>&1; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

#═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Fast Checks (Parallel)
#═══════════════════════════════════════════════════════════════════════════
print_section "1" "Fast Checks (Parallel)"
echo ""

# Run format and clippy in parallel
echo -e "${CYAN}  Running rustfmt and clippy...${NC}"

run_timed "rustfmt" "$LOG_DIR/fmt.log" cargo fmt -- --check &
FMT_PID=$!

run_timed "clippy" "$LOG_DIR/clippy.log" cargo clippy -- -D warnings &
CLIPPY_PID=$!

# Wait for both to complete
wait $FMT_PID
FMT_RESULT=$?
wait $CLIPPY_PID
CLIPPY_RESULT=$?

# Print results
echo ""
FMT_TIME=$(cat "$LOG_DIR/fmt.log.time" 2>/dev/null || echo "0")
CLIPPY_TIME=$(cat "$LOG_DIR/clippy.log.time" 2>/dev/null || echo "0")

if [ $FMT_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Code Formatting (${FMT_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Code Formatting (${FMT_TIME}s)"
    FAILED=1
fi

if [ $CLIPPY_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Clippy Linting (${CLIPPY_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Clippy Linting (${CLIPPY_TIME}s)"
    FAILED=1
fi

echo ""
PHASE1_TIME=$((FMT_TIME > CLIPPY_TIME ? FMT_TIME : CLIPPY_TIME))
echo -e "${BOLD}Phase 1 completed in ${PHASE1_TIME}s${NC}"
echo ""

# Exit early if phase 1 failed
if [ $FAILED -eq 1 ]; then
    echo -e "${RED}Fast checks failed. Fix issues before continuing.${NC}"
    exit 1
fi

#═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Build (Sequential - required for tests)
#═══════════════════════════════════════════════════════════════════════════
print_section "2" "Build (Sequential)"
echo ""
echo -e "${CYAN}  Building project...${NC}"

BUILD_START=$(date +%s)
if cargo build --verbose > "$LOG_DIR/build.log" 2>&1; then
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    echo -e "  ${GREEN}✓ PASS${NC}: Build (${BUILD_TIME}s)"
else
    BUILD_END=$(date +%s)
    BUILD_TIME=$((BUILD_END - BUILD_START))
    echo -e "  ${RED}✗ FAIL${NC}: Build (${BUILD_TIME}s)"
    echo ""
    echo -e "${RED}Build failed. See $LOG_DIR/build.log for details.${NC}"
    exit 1
fi

echo ""
echo -e "${BOLD}Phase 2 completed in ${BUILD_TIME}s${NC}"
echo ""

#═══════════════════════════════════════════════════════════════════════════
# PHASE 3: All Tests (Parallel)
#═══════════════════════════════════════════════════════════════════════════
print_section "3" "Test Suites (Parallel - 6 jobs)"
echo ""
echo -e "${CYAN}  Launching 6 test suites in parallel...${NC}"
echo ""

# Launch all test suites in parallel
run_timed "unit" "$LOG_DIR/unit.log" \
    cargo test --workspace --lib --verbose &
UNIT_PID=$!

run_timed "integration" "$LOG_DIR/integration.log" \
    cargo test --workspace --test integration_tests --verbose &
INTEGRATION_PID=$!

run_timed "attack" "$LOG_DIR/attack.log" \
    cargo test --package rust-v-hsm-can --test attack_regression_tests -- --ignored --test-threads=1 --nocapture &
ATTACK_PID=$!

run_timed "access" "$LOG_DIR/access.log" \
    cargo test --package rust-v-hsm-can --test access_control_regression_tests -- --ignored --test-threads=1 --nocapture &
ACCESS_PID=$!

run_timed "replay" "$LOG_DIR/replay.log" \
    cargo test --package rust-v-hsm-can --test replay_protection_regression_tests -- --ignored --test-threads=1 --nocapture &
REPLAY_PID=$!

run_timed "anomaly" "$LOG_DIR/anomaly.log" \
    cargo test --package autonomous_vehicle_sim --test anomaly_ids_regression_tests -- --ignored --test-threads=1 --nocapture &
ANOMALY_PID=$!

# Show progress while tests run
echo -e "${CYAN}  Waiting for tests to complete...${NC}"
PIDS=($UNIT_PID $INTEGRATION_PID $ATTACK_PID $ACCESS_PID $REPLAY_PID $ANOMALY_PID)
COMPLETED=0
TOTAL=6

while [ $COMPLETED -lt $TOTAL ]; do
    COMPLETED=0
    for pid in "${PIDS[@]}"; do
        if ! ps -p $pid > /dev/null 2>&1; then
            COMPLETED=$((COMPLETED + 1))
        fi
    done
    echo -ne "  Progress: ${COMPLETED}/${TOTAL} test suites completed\r"
    sleep 0.5
done
echo -ne "  Progress: ${TOTAL}/${TOTAL} test suites completed\n"
echo ""

# Wait for all and collect results
wait $UNIT_PID
UNIT_RESULT=$?
wait $INTEGRATION_PID
INTEGRATION_RESULT=$?
wait $ATTACK_PID
ATTACK_RESULT=$?
wait $ACCESS_PID
ACCESS_RESULT=$?
wait $REPLAY_PID
REPLAY_RESULT=$?
wait $ANOMALY_PID
ANOMALY_RESULT=$?

# Read timing information
UNIT_TIME=$(cat "$LOG_DIR/unit.log.time" 2>/dev/null || echo "0")
INTEGRATION_TIME=$(cat "$LOG_DIR/integration.log.time" 2>/dev/null || echo "0")
ATTACK_TIME=$(cat "$LOG_DIR/attack.log.time" 2>/dev/null || echo "0")
ACCESS_TIME=$(cat "$LOG_DIR/access.log.time" 2>/dev/null || echo "0")
REPLAY_TIME=$(cat "$LOG_DIR/replay.log.time" 2>/dev/null || echo "0")
ANOMALY_TIME=$(cat "$LOG_DIR/anomaly.log.time" 2>/dev/null || echo "0")

# Print results
if [ $UNIT_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Unit Tests (${UNIT_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Unit Tests (${UNIT_TIME}s)"
    FAILED=1
fi

if [ $INTEGRATION_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Integration Tests (${INTEGRATION_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Integration Tests (${INTEGRATION_TIME}s)"
    FAILED=1
fi

if [ $ATTACK_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Attack Detection Tests (${ATTACK_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Attack Detection Tests (${ATTACK_TIME}s)"
    FAILED=1
fi

if [ $ACCESS_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Access Control Tests (${ACCESS_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Access Control Tests (${ACCESS_TIME}s)"
    FAILED=1
fi

if [ $REPLAY_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Replay Protection Tests (${REPLAY_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Replay Protection Tests (${REPLAY_TIME}s)"
    FAILED=1
fi

if [ $ANOMALY_RESULT -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Anomaly IDS Tests (${ANOMALY_TIME}s)"
else
    echo -e "  ${RED}✗ FAIL${NC}: Anomaly IDS Tests (${ANOMALY_TIME}s)"
    FAILED=1
fi

# Calculate phase 3 duration (max of all parallel tests)
PHASE3_TIME=$UNIT_TIME
[ $INTEGRATION_TIME -gt $PHASE3_TIME ] && PHASE3_TIME=$INTEGRATION_TIME
[ $ATTACK_TIME -gt $PHASE3_TIME ] && PHASE3_TIME=$ATTACK_TIME
[ $ACCESS_TIME -gt $PHASE3_TIME ] && PHASE3_TIME=$ACCESS_TIME
[ $REPLAY_TIME -gt $PHASE3_TIME ] && PHASE3_TIME=$REPLAY_TIME
[ $ANOMALY_TIME -gt $PHASE3_TIME ] && PHASE3_TIME=$ANOMALY_TIME

echo ""
echo -e "${BOLD}Phase 3 completed in ${PHASE3_TIME}s${NC}"
echo ""

#═══════════════════════════════════════════════════════════════════════════
# Final Summary
#═══════════════════════════════════════════════════════════════════════════
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo "═══════════════════════════════════════════════════════════════════════════"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}                    ALL TESTS PASSED ✓${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${BOLD}Performance Summary:${NC}"
    echo "  Phase 1 (Fast Checks):  ${PHASE1_TIME}s"
    echo "  Phase 2 (Build):        ${BUILD_TIME}s"
    echo "  Phase 3 (All Tests):    ${PHASE3_TIME}s (6 parallel jobs)"
    echo "  ─────────────────────────────"
    echo -e "  ${BOLD}Total CI Time:          ${TOTAL_TIME}s${NC}"
    echo ""
    echo "You are ready to push your changes!"
    echo ""
    exit 0
else
    echo -e "${RED}${BOLD}                  SOME TESTS FAILED ✗${NC}"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${YELLOW}Check logs in: $LOG_DIR${NC}"
    echo ""
    echo "Failed test logs:"
    [ $FMT_RESULT -ne 0 ] && echo "  - $LOG_DIR/fmt.log"
    [ $CLIPPY_RESULT -ne 0 ] && echo "  - $LOG_DIR/clippy.log"
    [ $UNIT_RESULT -ne 0 ] && echo "  - $LOG_DIR/unit.log"
    [ $INTEGRATION_RESULT -ne 0 ] && echo "  - $LOG_DIR/integration.log"
    [ $ATTACK_RESULT -ne 0 ] && echo "  - $LOG_DIR/attack.log"
    [ $ACCESS_RESULT -ne 0 ] && echo "  - $LOG_DIR/access.log"
    [ $REPLAY_RESULT -ne 0 ] && echo "  - $LOG_DIR/replay.log"
    [ $ANOMALY_RESULT -ne 0 ] && echo "  - $LOG_DIR/anomaly.log"
    echo ""
    echo "Please fix the failing tests before pushing."
    echo ""

    # Prevent log cleanup on failure
    trap - EXIT
    echo -e "${CYAN}Logs preserved in: $LOG_DIR${NC}"
    echo ""
    exit 1
fi
