pattern = ['Stack-based buffer overflow', 'Arbitrary command execution', 'Obtain sensitive information',
           'Local privilege escalation', 'Security Feature Bypass', 'Out-of-bounds read', 'Out of bounds read',
           'Denial of service', 'Denial-of-service', 'Execute arbitrary code', 'Expose the credentials',
           'Cross-site scripting (XSS)', 'Privilege escalation', 'Reflective XSS Vulnerability',
           'Execution of arbitrary programs', 'Server-side request forgery (SSRF)', 'Stack overflow',
           'Execute arbitrary commands', 'Obtain highly sensitive information', 'Bypass security',
           'Remote Code Execution', 'Memory Corruption', 'Arbitrary code execution', 'CSV Injection',
           'Heap corruption', 'Out of bounds memory access', 'Sandbox escape', 'NULL pointer dereference',
           'Remote Code Execution', 'RCE', 'Authentication Error', 'Use-After-Free', 'Use After Free',
           'Corrupt Memory', 'Execute Untrusted Code', 'Run Arbitrary Code', 'heap out-of-bounds write',
           'OS Command injection', 'Elevation of Privilege', 'Race condition', 'Access violation', 'Infinite loop']

template = """
### Описание

{{d.cve}}

### Дата публикации

{{d.lastModifiedDate}}

### Дата выявления

{{d.publishedDate}}


### Продукт, вендор

<details>

{% for vendor in d.product_vendor_list %}{{vendor}}
{% endfor %}


</details>

### CVSSv3 Score

{{d.score}}

### CVSSv3 Vector

{{d.vector}}

### CPE
<details>

{% if d.configurations.nodes %}
{% for conf in d.configurations.nodes %}

#### Configuration {{ loop.index }}
{% if conf.operator == 'AND'%}{% set children = conf.children %}{% else %}{% set children = [conf] %}{% endif %}{% if children|length > 1 %}
**AND:**{% endif %}{% for child in children %}{% if child.cpe_match|length > 1 %}**OR:**{% endif %}{% for cpe in child.cpe_match %}
{{ cpe.cpe23Uri | replace("*", "\*") }}{% endfor %}{% endfor %}{% endfor %}
{% endif %}
</details>

### Links
<details>

{% for link in d.links %}{{ link }}
{% endfor %}


{% if d.exploit_links %}

### Exploit

{% for exploit in d.exploit_links %}{{exploit}}
{% endfor %}
{% endif %}

</details>


{%if d.kb_links %}

### Решение от майкрософт
<details>
<summary>Установить следующие обновления безопасности</summary>

{% for link in d.kb_links %}{{link}}
{% endfor %}
{% endif %}

</details>


{%if d.mitigations_links %}

### Mitigations от MITRE
<details>
<summary>Mitigation_ID and link</summary>

{% for link in d.mitigations_links %}{{link}}
{% endfor %}
{% endif %}

</details>
"""