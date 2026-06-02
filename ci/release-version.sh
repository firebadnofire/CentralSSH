#!/bin/sh
set -eu

repo_root=${REPO_ROOT:-$PWD}
tag=${FORGEJO_REF_NAME:-${GITHUB_REF_NAME:-}}

if [ -z "$tag" ]; then
  if command -v git >/dev/null 2>&1; then
    tag=$(git -C "$repo_root" describe --tags --exact-match HEAD 2>/dev/null || true)
  fi
fi

[ -n "$tag" ] || {
  echo "missing release tag for version derivation" >&2
  exit 1
}

case "$tag" in
  v*|V*)
    release_version=${tag#?}
    ;;
  *)
    echo "release tag must start with v or V: $tag" >&2
    exit 1
    ;;
esac

validate_semver() {
  version=$1
  core=$version
  prerelease=
  build=

  case "$core" in
    *+*)
      build=${core#*+}
      core=${core%%+*}
      [ -n "$build" ] || return 1
      ;;
  esac

  case "$core" in
    *-*)
      prerelease=${core#*-}
      core=${core%%-*}
      [ -n "$prerelease" ] || return 1
      ;;
  esac

  old_ifs=$IFS
  IFS=.
  set -- $core
  IFS=$old_ifs
  [ "$#" -eq 3 ] || return 1

  for part in "$@"; do
    case "$part" in
      ''|*[!0-9]*)
        return 1
        ;;
      0|[1-9]*)
        case "$part" in
          0[0-9]*)
            return 1
            ;;
        esac
        ;;
    esac
  done

  if [ -n "$prerelease" ]; then
    old_ifs=$IFS
    IFS=.
    set -- $prerelease
    IFS=$old_ifs
    [ "$#" -ge 1 ] || return 1
    for ident in "$@"; do
      case "$ident" in
        ''|*[!0-9A-Za-z-]*)
          return 1
          ;;
      esac
      case "$ident" in
        [0-9]*)
          case "$ident" in
            0|0[!0-9]*)
              ;;
            0[0-9]*)
              return 1
              ;;
          esac
          ;;
      esac
    done
  fi

  if [ -n "$build" ]; then
    old_ifs=$IFS
    IFS=.
    set -- $build
    IFS=$old_ifs
    [ "$#" -ge 1 ] || return 1
    for ident in "$@"; do
      case "$ident" in
        ''|*[!0-9A-Za-z-]*)
          return 1
          ;;
      esac
    done
  fi
}

validate_semver "$release_version" || {
  printf 'invalid semantic version derived from tag %s: %s\n' "$tag" "$release_version" >&2
  exit 1
}

printf 'release-version: release_tag=%s release_version=%s\n' "$tag" "$release_version" >&2
printf 'RELEASE_TAG=%s\n' "$tag"
printf 'RELEASE_VERSION=%s\n' "$release_version"
