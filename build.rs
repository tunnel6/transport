fn main() {
  // API-owned schema output and compatibility policy are committed in build/.
  // Sync with api/scripts/gen.sh sync-transport; standalone builds need no API checkout.
  napi_build::setup();
}
