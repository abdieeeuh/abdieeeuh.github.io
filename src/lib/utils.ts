import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

const LABEL_OVERRIDES: Record<string, string> = {
  'web-exploitation': 'Web Exploitation',
  'qualification-ara-7-0': 'Qualification ARA 7.0',
  'final-ara-7-0': 'Final ARA 7.0',
  misc: 'Misc',
  'reverse-engineering': 'Reverse Engineering',
  'binary-exploitation': 'Binary Exploitation',
  'web-exploit': 'Web Exploit',
  cryptography: 'Cryptography',
}

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: Date) {
  return Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(date)
}

export function formatLabel(value: string) {
  return (
    LABEL_OVERRIDES[value] ||
    value
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
  )
}

export function calculateWordCountFromHtml(
  html: string | null | undefined,
): number {
  if (!html) return 0
  const textOnly = html.replace(/<[^>]+>/g, '')
  return textOnly.split(/\s+/).filter(Boolean).length
}

export function readingTime(wordCount: number): string {
  const readingTimeMinutes = Math.max(1, Math.round(wordCount / 200))
  return `${readingTimeMinutes} min read`
}

export function getHeadingMargin(depth: number): string {
  const margins: Record<number, string> = {
    3: 'ml-4',
    4: 'ml-8',
    5: 'ml-12',
    6: 'ml-16',
  }
  return margins[depth] || ''
}
