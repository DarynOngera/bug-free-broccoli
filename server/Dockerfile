# Server: Elixir + Cowboy pinned to the vulnerable cowlib 2.18.0.
FROM elixir:1.17.3-otp-27

ENV MIX_ENV=prod
# OTP 27 auto-sizes max_ports (and thus the fixed port_table) up to 2^24 on
# high-memory hosts — that alone is ~1.5 GiB. Cap it so the VM baseline is
# ~35 MiB and the exploit's memory spike is observable within mem_limit.
ENV ERL_AFLAGS="+Q 262144"

WORKDIR /app

RUN mix local.hex --force && mix local.rebar --force

# Fetch dependencies first for better layer caching.
COPY mix.exs ./
RUN mix deps.get && mix deps.compile

COPY poc_server.exs ./

EXPOSE 8080

CMD ["mix", "run", "poc_server.exs"]