/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      if (typeof orderLinesData !== 'string') {
        return next(new Error('Invalid input'))
      }

      // 1. If it's a valid JSON, parse it safely and completely bypass safeEval/vm!
      let isValidJson = false
      try {
        JSON.parse(orderLinesData)
        isValidJson = true
      } catch (err) {
        // Not valid JSON, which is fine, might be a challenge solver or broken input
      }

      if (isValidJson) {
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
        return
      }

      // 2. If it's not valid JSON, check for blocked patterns.
      // We block any property access using brackets or backticks, or any dangerous keywords.
      const containsBlocked = /\b(this|process|require|exec|spawn|Function|eval|global|globalThis|window|document|import|Reflect|Object|Proxy|Symbol|setTimeout|setInterval|arguments|caller|callee)\b/i.test(orderLinesData) ||
        /constructor|__proto__|prototype|child_process/i.test(orderLinesData)
      const containsBackslash = orderLinesData.includes('\\')
      
      // If the input is not JSON, we forbid any brackets [ ] or backticks ` `
      const containsForbiddenChars = /[\[\]`]/.test(orderLinesData)

      if (containsBlocked || containsBackslash || containsForbiddenChars) {
        return next(new Error('Blocked malicious input'))
      }

      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
