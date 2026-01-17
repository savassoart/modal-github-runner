import modal

runner_image = modal.Image.debian_slim().apt_install(
    'curl',
    'git',
    'ca-certificates',
    'sudo',
    'jq'
).run_commands(
    'mkdir /actions-runner',
    'curl -L https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz | tar -xz -C /actions-runner',
    '/actions-runner/bin/installdependencies.sh'
)
