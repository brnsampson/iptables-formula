# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set strict_mode = firewall.get('strict', False) %}
  {% set global_block_nomatch = firewall.get('block_nomatch', False) %}
  {% set packages = salt['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables'],
    'default': 'Debian'}) %}

    {%- if install %}
      # Install required packages for firewalling      
      iptables_packages:
        pkg.installed:
          - pkgs:
            {%- for pkg in packages %}
            - {{pkg}}
            {%- endfor %}
    {%- endif %}

    {%- if strict_mode %}
      # If the firewall is set to strict mode, we'll need to allow some 
      # that always need access to anything
      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True

      # Allow related/established sessions
      iptables_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True            

      # Set the policy to deny everything unless defined
      enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established
    {%- endif %}

  # Generate ipsets for all services that we have information about
  {%- for service_name, service_details in firewall.get('services', {}).items() %}  
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set interfaces = service_details.get('interfaces','') %}
    {% set protos = service_details.get('protos',['tcp']) %}
    {% if service_details.get('comment', False) %}
      {% set comment = '- comment: ' + service_details.get('comment') %}
    {% else %}
      {% set comment = '' %}
    {% endif %}

    # Allow rules for ips/subnets
    {%- if service_details.get('ips_allow', []) %}
      {%- for ip in service_details.get('ips_allow', []) %}
        {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          {%- if interfaces }
          - i: {{ ','.join(interfaces) }}
          {% endif }
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
        {%- endfor %}
      {%- endfor %}
    {%- else }
      {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          {%- if interfaces }
          - i: {{ ','.join(interfaces) }}
          {% endif }
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
      {%- endfor %}
    {%- endif }

    {%- if not strict_mode and global_block_nomatch or block_nomatch %}
      # If strict mode is disabled we may want to block anything else
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}_{{interface}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - i: {{ interface }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
          {%- endfor %}
        {%- endfor %}
      {%- endif %}

    {%- endif %}    

  {%- endfor %}

  # Generate rules for NAT
  {%- for rule in firewall.get('nat', []) %}  
    {%- if rule.get('dport') %}
      iptables_{{rule['chain']}}_{{rule['jump']}}_{{rule['dport']}}:
    {%- elif rule.get('interface') %}
      iptables_{{rule['chain']}}_{{rule['jump']}}_{{rule['interface']}}:
    {%- else %}
      iptables_{{rule['chain']}}_{{rule['jump']}}:
    {%- endif %}
        iptables.append:
          - table: nat 
          - chain: {{ rule.get('chain', 'POSTROUTING') }}
          - jump: {{ rule.get('jump', 'MASQUERADE') }}
          {%- if rule.get('interface', None) %}
          - o: {{ rule['interface'] }} 
          {%- endif %}
          {%- if rule.get('source_ip', None) %}
          - source: {{ rule['source_ip'] }}
          {%- endif %}
          {%- if rule.get('destination_ip', None) %}
          - to-destination: {{ rule['destination_ip'] }}
          {%- endif %}
          {%- if rule.get('proto', None) %}
          - proto: {{ rule['proto'] }}
          {%- endif %}
          {%- if rule.get('dport', None) %}
          - dport: {{ rule['dport'] }}
          {%- endif %}
          - save: True
  {%- endfor %}

  # Generate rules for forwarding
  {%- for rule in firewall.get('forwarding', []) %}  
    {%- if rule.get('dport') %}
      iptables_forward_{{rule['dport']}}_{{rule['destination_ip']}}:
    {%- else %}
      iptables_forward_{{rule['destination_ip']}}:
    {%- endif %}
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - destination: {{ rule['destination_ip'] }}
          {%- if rule.get('interface', None) %}
          - o: {{ rule['interface'] }} 
          {%- endif %}
          {%- if rule.get('source_ip', None) %}
          - source: {{ rule['source_ip'] }}
          {%- endif %}
          {%- if rule.get('proto', None) %}
          - proto: {{ rule['proto'] }}
          {%- endif %}
          {%- if rule.get('dport', None) %}
          - dport: {{ rule['dport'] }}
          {%- endif %}
          - save: True
  {%- endfor %}

  # Generate rules for whitelisting IP classes
  {%- for service_name, service_details in firewall.get('whitelist', {}).items() %}
    {%- for ip in service_details.get('ips_allow', []) %}
      iptables_{{service_name}}_allow_{{ip}}:
        iptables.append:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
    {%- endfor %}
  {%- endfor %}

{%- endif %}
