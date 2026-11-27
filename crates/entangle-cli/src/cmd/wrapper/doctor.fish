# Fish implements aliases as functions. Keep the definition in the current shell.
set -g __entangle_claude_definition (functions claude-code | string collect)
if not functions -q entangle
  function entangle
    if test "$argv[1]" = doctor; or test "$argv[1] $argv[2]" = "--allow-local doctor"
      set -lx ENTANGLE_WRAPPER_RESOLUTION shadowed
      if functions -q claude-code; and test (functions claude-code | string collect) = "$__entangle_claude_definition"
        set ENTANGLE_WRAPPER_RESOLUTION active
      end
      command entangle $argv
    else
      command entangle $argv
    end
  end
end
