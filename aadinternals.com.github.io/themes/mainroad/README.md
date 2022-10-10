# Mainroad

**Mainroad** is a responsive, simple, clean and content-focused [Hugo](https://gohugo.io/) theme based on the [MH Magazine lite](https://wordpress.org/themes/mh-magazine-lite/) WordPress theme by [MH Themes](https://www.mhthemes.com/).

**[Alternate Demo (Best)](https://hugothemes.gitlab.io/mainroad/)** | [Standart Demo](https://themes.gohugo.io/theme/mainroad/)

![screenshot](https://github.com/Vimux/mainroad/blob/master/images/screenshot.png)

**Adaptation has several changes:**

+ Include Hugo internal templates (Open Graph, Disqus, Google Analytics)
+ New responsive menu without jQuery
+ BEM-like class naming
+ SVG icons instead of font icons
+ Theme options are saved (Sidebar position, Author Box, Post Navigation) and available through config.toml file parameters
+ Other small changes

**Browser support:**

+ **Desktop:** IE9+, Chrome, Firefox, Safari
+ **Mobile:** Android browser (on Android 4.4+), Safari (on iOS 7+), Google Chrome, Opera mini

Other browsers (like Opera on Blink engine) are also supported, but not tested. Support for older versions of Internet Explorer (IE8 and below) ended.

## Installation

In your Hugo site `themes` directory, run:

```
$ git clone https://github.com/vimux/mainroad
```

Next, open `config.toml` in the base of the Hugo site and ensure the theme option is set to `mainroad`:

```
theme = "mainroad"
```

For more information read the official [setup guide](https://gohugo.io/themes/installing-and-using-themes/) of Hugo.

## Configuration

### Config.toml example

```toml
baseurl = "/"
title = "Mainroad"
languageCode = "en-us"
paginate = "10" # Number of posts per page
theme = "mainroad"
disqusShortname = "" # Enable comments by entering your Disqus shortname
googleAnalytics = "" # Enable Google Analytics by entering your tracking id

[Author] # Used in authorbox
    name = "John Doe"
    bio = "John Doe's true identity is unknown. Maybe he is a successful blogger or writer. Nobody knows it."
    avatar = "img/avatar.png"

[Params]
    subtitle = "Just another site" # Subtitle of your site. Used in site header
    description = " John Doe's Personal blog about everything" # Description of your site. Used in meta description
    opengraph = true # Enable OpenGraph if true
    readmore = false # Show "Read more" button in list if true
    leftsidebar = false # Move sidebar to the left side if true
    authorbox = true # Show authorbox at bottom of pages if true
    post_navigation = true # Show post navigation at bottom of pages if true
    postSections = ["post"] # the section pages to show on home page and the "Recent articles" widget
    #postSections = ["blog", "news"] # alternative that shows more than one section's pages
    #dateformat = "2006-01-02" # change the format of dates

[Params.widgets]
    search = true # Enable "Search" widget
    recent_articles = true # Enable "Recent articles" widget
    recent_articles_num = 5 # Set the number of articles in the "Recent articles" widget
    categories = true # Enable "Categories" widget
    tags = true # Enable "Tags" widget
    tags_counter = false # Enable counter for each tag in "Tags" widget (disabled by default)

    # Enable "Social" widget, if any of "social_*" set a value
    social_facebook = "username"
    social_twitter = "username"
    social_linkedin = "username"
    social_github = "username"
    social_email = "example@example.com"
```

### Front Matter example

```toml
+++
title = "Example article title"
date = "2017-08-21"
description = "Example article description"
thumbnail = "img/placeholder.jpg" # Optional, thumbnail
disable_comments = false # Optional, disable Disqus comments if true
+++
```

For more information about front matter variables read [Hugo Front Matter](https://gohugo.io/themes/installing-and-using-themes/) from Hugo official documentation.

## Contributing

Have you found a bug or got an idea for a new feature? Feel free to use the [issue tracker](https://github.com/Vimux/mainroad/issues) to let me know. Or make directly a [pull request](https://github.com/Vimux/mainroad/pulls).

## License

This theme is released under the [GPLv2 license](https://github.com/Vimux/mainroad/blob/master/LICENSE.md) (inherited from the original MH Magazine lite WordPress theme).
