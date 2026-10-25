defmodule PocServer.MixProject do
  use Mix.Project

  def project do
    [
      app: :poc_server,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      # Cowboy 2.17.0 is the release that ships the vulnerable cowlib 2.18.0
      # (cowlib 2.19.0 is bundled with cowboy 2.18.0). Cowboy pins an exact
      # cowlib, so cowlib is forced below with override: true to make the
      # vuln<->fix demonstration a one-line change.
      {:cowboy, "2.17.0"},
      # Pin the vulnerable cowlib (before 2.19.0). Bump to "2.19.0" to verify the fix.
      {:cowlib, "2.18.0", override: true},
      # Cowboy 2.17.0 is tested against ranch 1.8.1; without this pin Mix
      # resolves ranch 2.x, whose transport-option handling breaks
      # :cowboy.start_clear/3 (num_acceptors -> badarg in ranch_acceptors_sup).
      {:ranch, "1.8.1"},
      # prometheus_ex 3.1.0 drags in prometheus 4.x, which ships the
      # BEAM VM collectors (erlang_vm_* memory metrics) and
      # prometheus_text_format/0 for rendering the /metrics endpoint.
      {:prometheus_ex, "3.1.0"}
    ]
  end
end
