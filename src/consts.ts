import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: 'Abdieeuh',
  description:
    'I keep documentation of completed challenges here',
  href: 'https://abdieeuh.github.io',
  author: 'Abdieeuh',
  locale: 'en-US',
  featuredPostCount: 2,
  postsPerPage: 3,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
  {
    href: '/categories',
    label: 'categories',
  },
  {
    href: '/about',
    label: 'about',
  },
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}

export const EVENT_CATEGORIES = ['qualification-ara-7-0', 'final-ara-7-0']
