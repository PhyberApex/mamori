---
layout: page
title: Check reference
permalink: /checks/
---

Each check mamori performs is documented here. Every finding includes a link to the relevant page so you can understand the issue and fix it without leaving your terminal.

| Check | Severity |
|---|---|
{% for check in site.data.checks %}{% if check.slug %}| [{% if check.label %}{{ check.label }}{% elsif check.code %}`{{ check.name }}`{% else %}{{ check.name }}{% endif %}]({{ check.slug }}){% if check.opt_in %} (opt-in){% endif %} | {{ check.severity }} |
{% endif %}{% endfor %}
