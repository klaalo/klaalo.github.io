---
layout: page
title: Ehdokkuuteni vaaleissa
permalink: /vaalit/
---

{% assign posts = site.categories.vaalit | sort: 'date' | reverse %}
{% if posts.size > 0 %}
<ul>
  {% for post in posts %}
    <li><a href="{{ post.url }}">{{ post.title }}</a> — {{ post.date | date: "%-d.%-m.%Y" }}</li>
  {% endfor %}
</ul>
{% else %}
<p>Ei vielä kirjoituksia tässä kategoriassa.</p>
{% endif %}