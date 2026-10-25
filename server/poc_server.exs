# Cowboy (Elixir) server vulnerable to the cowlib HPACK oversized-integer
# DoS (cowlib < 2.19.0), with a Prometheus /metrics endpoint served from
# the same clear-text listener so the VM memory spike is observable.
#
# Run with:  mix run poc_server.exs

{:ok, _} = :application.ensure_all_started(:cowboy)
{:ok, _} = :application.ensure_all_started(:prometheus_ex)

# Register the BEAM VM collectors on the default registry (idempotent).
# This exposes erlang_vm_memory_bytes_total / erlang_vm_memory_*
# and friends, which drive the Grafana memory panels.
:prometheus_registry.register_collectors([
  :prometheus_vm_memory_collector,
  :prometheus_vm_statistics_collector,
  :prometheus_vm_system_info_collector
])

defmodule PocHandler do
  def init(req, state) do
    # Cowboy 2.x reply/4 returns the bare Req (not {ok, Req}).
    req2 = :cowboy_req.reply(200, %{"content-type" => "text/plain"}, "OK", req)
    {:ok, req2, state}
  end
end

# cgroup v2 container memory, read straight from this container's cgroup.
# `docker stats` reports memory.current minus inactive_file, so exposing the
# same figure lets Grafana track the container-level number (which includes
# allocator carriers and page cache) rather than only BEAM process heaps.
defmodule CgroupMemory do
  @current "/sys/fs/cgroup/memory.current"
  @peak "/sys/fs/cgroup/memory.peak"
  @max "/sys/fs/cgroup/memory.max"
  @stat "/sys/fs/cgroup/memory.stat"

  defp read_int(path) do
    with {:ok, raw} <- File.read(path),
         {n, _} <- Integer.parse(String.trim(raw)) do
      n
    else
      _ -> nil
    end
  end

  defp inactive_file do
    case File.read(@stat) do
      {:ok, raw} ->
        raw
        |> String.split("\n", trim: true)
        |> Enum.find_value(0, fn line ->
          case String.split(line, " ", parts: 2) do
            ["inactive_file", v] ->
              case Integer.parse(String.trim(v)) do
                {n, _} -> n
                :error -> nil
              end

            _ ->
              nil
          end
        end)

      _ ->
        0
    end
  end

  def metrics do
    current = read_int(@current)
    peak = read_int(@peak)
    limit = read_int(@max)
    used = if current, do: max(current - inactive_file(), 0)

    [
      {"cowboy_container_memory_used_bytes",
       "Container memory usage minus inactive file cache (matches `docker stats`).",
       used},
      {"cowboy_container_memory_current_bytes", "Raw cgroup memory.current (includes page cache).",
       current},
      {"cowboy_container_memory_peak_bytes",
       "Highest cgroup memory.current since the container started.", peak},
      {"cowboy_container_memory_limit_bytes", "cgroup memory.max for this container.", limit}
    ]
    |> Enum.flat_map(fn {name, help, value} ->
      if is_integer(value) do
        ["# HELP #{name} #{help}", "# TYPE #{name} gauge", "#{name} #{value}"]
      else
        []
      end
    end)
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end
end

defmodule MetricsHandler do
  def init(req, state) do
    body = :prometheus_text_format.format() <> CgroupMemory.metrics()
    headers = %{"content-type" => "text/plain; version=0.0.4; charset=utf-8"}

    req2 = :cowboy_req.reply(200, headers, body, req)
    {:ok, req2, state}
  end
end

# Routes: /metrics for Prometheus, everything else answers OK.
dispatch =
  :cowboy_router.compile([
    {:_, [{"/metrics", MetricsHandler, []}, {:_, PocHandler, []}]}
  ])

# Clear TCP listener: serves HTTP/1.1 and HTTP/2-over-cleartext (h2c,
# prior-knowledge preface) on the same port.
{:ok, _} =
  :cowboy.start_clear(
    :poc_listener,
    [port: 8080],
    %{
      env: %{dispatch: dispatch},
      # Raise the default cap (16384) so the oversized HPACK block is
      # fed to the decoder and the O(n²) bignum churn becomes visible
      # in Grafana as a multi-second memory spike.
      max_fragmented_header_block_size: 1048576
    }
  )

IO.puts("Cowboy serving http://0.0.0.0:8080 (HTTP/2 h2c enabled)")
IO.puts("Prometheus metrics: http://0.0.0.0:8080/metrics")

# Keep the VM alive.
Process.sleep(:infinity)