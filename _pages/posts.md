---
layout: single
author_profile: true
title: Posts
header:
  overlay_image: blog-cover.jpg
permalink: /posts.html
---

<ul>
{% for post in site.posts %}
  {% assign currentdate = post.date | date: "%Y" %}
  {% if currentdate != date %}
    <h2>{{ currentdate }}</h2>
    {% assign date = currentdate %} 
  {% endif %}
    <h3><a href="{{ post.url }}">{{ post.title }}</a></h3>
    {{ post.excerpt | markdownify | strip_html }}
{% endfor %}
</ul>
