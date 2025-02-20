# This script will autopull flags for designs that have little to no security
flagLengthInBytes=32;

aboveText=$(cat frame_playback.json | grep  -oE ".{0,$flagLengthInBytes}5e20666c6167205e" | head -1 | cut -c1-$flagLengthInBytes | xxd -r -p)

flag="ectf{recording_$aboveText}"

echo $flag
