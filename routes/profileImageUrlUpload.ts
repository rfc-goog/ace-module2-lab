/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function convertIpv4MappedToIpv4 (ip: string): string | null {
  const normalized = ip.toLowerCase().trim()
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = ip.substring(7)
    if (ipv4Part.includes('.')) return ipv4Part
    const segments = ipv4Part.split(':')
    if (segments.length === 2) {
      const high = parseInt(segments[0], 16)
      const low = parseInt(segments[1], 16)
      if (!isNaN(high) && !isNaN(low)) {
        const p0 = (high >> 8) & 255
        const p1 = high & 255
        const p2 = (low >> 8) & 255
        const p3 = low & 255
        return `${p0}.${p1}.${p2}.${p3}`
      }
    }
  }
  return null
}

function isPrivateIp (ip: string): boolean {
  const mapped = convertIpv4MappedToIpv4(ip)
  if (mapped) ip = mapped

  // Check IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const match = ip.match(ipv4Regex)
  if (match) {
    const parts = match.slice(1).map(Number)
    if (parts.some(p => p < 0 || p > 255)) return true
    const [p0, p1, p2, p3] = parts

    // Loopback: 127.0.0.0/8
    if (p0 === 127) return true
    // Private ranges
    if (p0 === 10) return true
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true
    if (p0 === 192 && p1 === 168) return true
    // Link-local: 169.254.0.0/16
    if (p0 === 169 && p1 === 254) return true
    // Unspecified: 0.0.0.0
    if (p0 === 0) return true
    // Shared address space: 100.64.0.0/10
    if (p0 === 100 && p1 >= 64 && p1 <= 127) return true
    // Multicast & Reserved: 224.0.0.0/4 and 240.0.0.0/4
    if (p0 >= 224) return true
  }

  // Check IPv6
  if (ip.includes(':')) {
    const normalized = ip.toLowerCase().trim()
    // Loopback: ::1
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true
    // Unspecified: ::
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true
    // Unique Local Address (ULA): fc00::/7
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
    // Link-local: fe80::/10
    if (/^fe[89ab]/i.test(normalized)) return true
  }

  return false
}

async function validateUrlForSsrf (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '')

    // Perform DNS lookup to check all resolved IP addresses
    const lookupResult = await dns.promises.lookup(hostname, { all: true })

    for (const entry of lookupResult) {
      if (isPrivateIp(entry.address)) {
        return false
      }
    }

    return true
  } catch (err) {
    return false
  }
}

async function safeFetch (urlStr: string, maxRedirects = 5): Promise<any> {
  let currentUrl = urlStr
  for (let i = 0; i <= maxRedirects; i++) {
    const isSafe = await validateUrlForSsrf(currentUrl)
    if (!isSafe) {
      throw new Error('Blocked SSRF attempt to internal/private target')
    }

    const response = await fetch(currentUrl, { redirect: 'manual' })

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        return response
      }

      currentUrl = new URL(location, currentUrl).toString()
      continue
    }

    return response
  }

  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const isSafe = await validateUrlForSsrf(url)
        if (!isSafe) {
          next(new Error('Blocked illegal activity'))
          return
        }

        try {
          const response = await safeFetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error: any) {
          if (error.message === 'Blocked SSRF attempt to internal/private target' || error.message === 'Too many redirects') {
            next(error)
            return
          }
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
