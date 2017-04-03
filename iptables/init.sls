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
      iptables_allow_loopback:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.0/8
          - destination: 127.0.0.0/8
          - i: lo
          - save: True

      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True

      # Allow related/established sessions
      iptables_INPUT_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True

      iptables_FORWARD_allow_established:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True            

      # Set the policy to deny everything unless defined
      enable_INPUT_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_INPUT_allow_established
      enable_FORWARD_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: FORWARD
          - policy: DROP
          - require:
            - iptables: iptables_FORWARD_allow_established
    {%- endif %}

  # Create rule sets. The hierarchy is table -> chain -> [{default options}, [match], {extension options}]
  {%- for table_name, chains in firewall.get('tables', {}).items() %}
    {%- for chain_name, chain_specs in chains.items() %}
      {%- for chain_spec in chain_specs %}
        {%- set name_list = [table_name, chain_name, chain_spec['jump']] %}
        {%- if chain_spec.get('proto') %}
          {%- do name_list.append('_proto:{}'.format(chain_spec['proto'])) %}
        {%- endif %}
        {%- if chain_spec.get('in-interface') %}
          {%- do name_list.append('_in-interface:{}'.format(chain_spec['in-interface'])) %}
        {%- endif %}
        {%- if chain_spec.get('out-interface') %}
          {%- do name_list.append('_out-interface:{}'.format(chain_spec['out-interface'])) %}
        {%- endif %}
        {%- if chain_spec.get('source') %}
          {%- do name_list.append('_source:{}'.format(chain_spec['source'])) %}
        {%- endif %}
        {%- if chain_spec.get('destination') %}
          {%- do name_list.append('_destination:{}'.format(chain_spec['destination'])) %}
        {%- endif %}
        {%- for match_name, match_spec in chain_spec.get('match', {}).items() %}
          {%- do name_list.append('_match:{}'.format(match_name)) %}
          {%- for key_name, value in match_spec.items() %}
            {%- do name_list.append('{}:{}'.format(key_name, value)) %}
          {%- endfor %}
        {%- endfor %}
        {%- for key_name, value in chain_spec.get('extension_parameters', {}).items() %}
          {%- do name_list.append('{}:{}'.format(key_name, value)) %}
        {%- endfor %}
      iptables_{{ '_'.join(name_list) }}:
        iptables.append:
          - table: {{ table_name }}
          - chain: {{ chain_name }}
          - jump: {{ chain_spec['jump'] }}
        {%- if chain_spec.get('proto') %}
          - proto: {{ chain_spec.get('proto') }}
        {%- endif %}
        {%- if chain_spec.get('in-interface') %}
          - in-interface: {{ chain_spec.get('in-interface') }}
        {%- endif %}
        {%- if chain_spec.get('out-interface') %}
          - out-interface: {{ chain_spec.get('out-interface') }}
        {%- endif %}
        {%- if chain_spec.get('source') %}
          - source: {{ chain_spec.get('source') }}
        {%- endif %}
        {%- if chain_spec.get('destination') %}
          - destination: {{ chain_spec.get('destination') }}
        {%- endif %}
        {%- if chain_spec.get('match', {}) %}
          {%- set match_names = [] %}
          {%- for match_name, match_spec in chain_spec.get('match', {}).items() %}
            {%- do match_names.append(match_name) %}
            {%- for key_name, value in match_spec.items() %}
          - {{ key_name }}: {{ value }}
            {%- endfor %}
          - match: {{ match_names }}
          {%- endfor %}
        {%- endif %}
        {%- for key_name, value in chain_spec.get('extension_parameters', {}).items() %}
          - {{ key_name }}: {{ value }}
        {%- endfor %}
          - save: True
      {%- endfor %}
    {%- endfor %}
  {%- endfor %}

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
          {%- if interfaces %}
          - i: {{ ','.join(interfaces) }}
          {%- endif %}
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          {%- if service_details.get('state') %}
          - match: state
          - connstate: {{ service_details['state'] }}
          {%- endif %}
          - save: True
          {{ comment }}
        {%- endfor %}
      {%- endfor %}
    {%- else %}
      {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          {%- if interfaces %}
          - i: {{ ','.join(interfaces) }}
          {%- endif %}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          {%- if service_details.get('state') %}
          - match: state
          - connstate: {{ service_details['state'] }}
          {%- endif %}
          - save: True
          {{ comment }}
      {%- endfor %}
    {%- endif %}

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
