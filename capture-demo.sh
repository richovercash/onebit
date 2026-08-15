#!/usr/bin/env bash
# Capture the gate -> wallet -> GRANT flow off a connected phone.
#
#   ./capture-demo.sh [outfile]      default: onebit-demo-capture.mp4
#
# Run it with a finger already resting near the sensor. The script resets the
# phone to the gate page, starts recording, taps the button for you, and then
# waits for YOU — it polls until the biometric prompt goes away, so the take is
# only as long as it needs to be. No coordinating over chat.
#
# Needs the gate running:  JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
#                          ./gradlew :verifier:demoServer
set -euo pipefail
cd "$(dirname "$0")"

OUT=${1:-onebit-demo-capture.mp4}
DEV=/sdcard/onebit-capture.mp4
BTN_X=${BTN_X:-423}    # "Verify with OneBit wallet", 1440x3120 coords
BTN_Y=${BTN_Y:-886}

curl -sf -o /dev/null --max-time 5 http://localhost:8317/ || {
  echo "gate not up on :8317 — start :verifier:demoServer first"; exit 1; }
adb reverse tcp:8317 tcp:8317 >/dev/null

# Clear any biometric prompt left over from an abandoned run, or the wallet
# refuses to start a second one.
adb shell input keyevent KEYCODE_BACK >/dev/null 2>&1 || true
adb shell am start -a android.intent.action.VIEW -d 'http://localhost:8317/' \
  com.android.chrome >/dev/null 2>&1
until adb shell dumpsys window | grep -q 'mCurrentFocus.*chrome'; do sleep 1; done

echo "recording — tapping the button now, put your finger on the sensor"
adb shell screenrecord --size 720x1560 --bit-rate 4M --time-limit 120 "$DEV" &
REC=$!
sleep 2                      # let the encoder get a few frames of the gate page
adb shell input tap "$BTN_X" "$BTN_Y"

# ponytail: poll the focused window rather than guess a duration. The prompt
# appears, you authenticate, it disappears -> that's the end of the interesting
# part. 120s cap is the backstop if nobody ever touches it.
for _ in $(seq 60); do
  sleep 1
  adb shell dumpsys window | grep -q 'BiometricPrompt' && break
done
for _ in $(seq 60); do
  sleep 1
  adb shell dumpsys window | grep -q 'BiometricPrompt' || break
done
sleep 6                      # let the proof land and the verdict page render

adb shell pkill -INT screenrecord 2>/dev/null || true
wait $REC 2>/dev/null || true
sleep 2                      # screenrecord needs a moment to finalise the mp4

adb pull "$DEV" "$OUT" && adb shell rm -f "$DEV"

# screenrecord writes variable frame rate; players stutter on it. Normalise.
if command -v ffmpeg >/dev/null; then
  ffmpeg -y -v error -i "$OUT" -vf fps=30 -c:v libx264 -crf 21 -preset slow \
    -pix_fmt yuv420p -movflags +faststart "${OUT%.mp4}-smooth.mp4"
  echo "wrote ${OUT%.mp4}-smooth.mp4 (constant 30fps)"
fi
echo "done: $OUT"
