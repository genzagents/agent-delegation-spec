// Section 4: scope grammar, the `fin` vocabulary, scope classes, and the per-request scope check.
                                                                 
                                                           
                             
                 
                   
                                                                      
                                                                                                                      
 

export const FIN_VOCABULARY                             = {
  "account.read": "read", "account.export": "read", "payment.initiate": "move", "payment.cancel": "move",
  "payee.add": "admin", "card.freeze": "admin", "profile.read": "read", "profile.write": "admin",
};
export const CLASS_DEFAULTS                                                                                          = {
  read: { maxValidityDays: 365, verification: "light" },
  move: { maxValidityDays: 90, verification: "kyc" },
  admin: { maxValidityDays: 30, verification: "kyc" },
  forbidden: { maxValidityDays: 0, verification: "kyc" },
};

export function actionClass(action        )                         {
  if (action.startsWith("credential.")) return "forbidden";
  return FIN_VOCABULARY[action];
}

/** `*` is allowed only as the whole last segment: `acct:*` matches `acct:gb29...`, `acct:gb*` does not. */
export function resourceMatches(pattern        , resource        )          {
  if (pattern === resource) return true;
  const i = pattern.lastIndexOf(":");
  if (!pattern.endsWith(":*") || i < 0) return false;
  return resource.startsWith(pattern.slice(0, i + 1)) && !resource.slice(i + 1).includes(":");
}

/** What the relying party knows about the request it is about to allow. */
                          
                 
                   
                 
                                                                                              
                                                                                             
                                                                                         
 
                                                                                                                  

export function checkScope(scope              , req         )                {
  const cls = actionClass(req.action);
  if (!cls) return { allowed: false, reason: `unknown action '${req.action}' (not in the fin vocabulary)` };
  if (cls === "forbidden") return { allowed: false, reason: `action '${req.action}' is never delegable` };
  const entry = scope.find((e) => e.action === req.action && resourceMatches(e.resource, req.resource));
  if (!entry) return { allowed: false, reason: `no scope entry grants ${req.action} on ${req.resource}` };
  const lim = entry.limits ?? {};
  if (lim.perTxn) {
    if (!req.amount) return { allowed: false, reason: "amount required by perTxn limit", entry };
    if (req.amount.currency !== lim.perTxn.currency || req.amount.amount > lim.perTxn.amount)
      return { allowed: false, reason: `amount ${req.amount.amount} ${req.amount.currency} exceeds perTxn limit ${lim.perTxn.amount} ${lim.perTxn.currency}`, entry };
  }
  if (lim.perPeriod) {
    if (!req.amount) return { allowed: false, reason: "amount required by perPeriod limit", entry };
    const spent = req.spentInPeriod?.amount ?? 0;
    if (req.amount.currency !== lim.perPeriod.currency || spent + req.amount.amount > lim.perPeriod.amount)
      return { allowed: false, reason: `amount ${req.amount.amount} plus ${spent} already spent exceeds perPeriod limit ${lim.perPeriod.amount} ${lim.perPeriod.currency} per ${lim.perPeriod.period}`, entry };
  }
  const con = entry.constraints ?? {};
  if (con.payeeAllowlist) {
    if (!req.payeeHash || !con.payeeAllowlist.includes(req.payeeHash)) return { allowed: false, reason: "payee not on payeeAllowlist", entry };
  }
  let stepUpRequired = cls === "admin";
  if (con.requireStepUp && req.amount && req.amount.currency === con.requireStepUp.above.currency && req.amount.amount > con.requireStepUp.above.amount) stepUpRequired = true;
  if (stepUpRequired && !req.stepUpSatisfied) return { allowed: false, reason: "step-up (fresh human confirmation) required and not satisfied", entry, stepUpRequired };
  return { allowed: true, entry, stepUpRequired };
}
