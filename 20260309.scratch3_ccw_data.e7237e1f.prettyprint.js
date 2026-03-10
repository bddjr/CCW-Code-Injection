/*! For license information please see scratch3_ccw_data.e7237e1f.js.LICENSE.txt */
"use strict";
(self.webpackChunkscratch_extensions = self.webpackChunkscratch_extensions || []).push([[194], {
    12960: (t, e, r) => {
        r.d(e, {
            Z: () => y,
            w: () => l
        });
        var a = r(36808)
          , n = r.n(a)
          , o = r(17563)
          , c = r(97865)
          , i = ["page", "perPage", "sortField", "sortType"];
        function s(t, e) {
            var r = Object.keys(t);
            if (Object.getOwnPropertySymbols) {
                var a = Object.getOwnPropertySymbols(t);
                e && (a = a.filter((function(e) {
                    return Object.getOwnPropertyDescriptor(t, e).enumerable
                }
                ))),
                r.push.apply(r, a)
            }
            return r
        }
        function u(t, e, r) {
            return e in t ? Object.defineProperty(t, e, {
                value: r,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : t[e] = r,
            t
        }
        var l = {
            USER: "user",
            PROJECT: "project"
        }
          , h = {
            CCW: {
                set: "/cloud_variable/save",
                get: "/cloud_variable/detail/v2",
                getList: "/cloud_variable/list"
            },
            COCREA: {
                set: "/cloud-variables",
                get: "/cloud-variables/detail",
                getList: "/cloud_variable/list"
            }
        }
          , f = function(t, e) {
            var r = e.page
              , a = e.perPage
              , n = e.sortField
              , c = e.sortType
              , l = void 0 === c ? "DESC" : c
              , h = function(t, e) {
                if (null == t)
                    return {};
                var r, a, n = function(t, e) {
                    if (null == t)
                        return {};
                    var r, a, n = {}, o = Object.keys(t);
                    for (a = 0; a < o.length; a++)
                        r = o[a],
                        e.indexOf(r) >= 0 || (n[r] = t[r]);
                    return n
                }(t, e);
                if (Object.getOwnPropertySymbols) {
                    var o = Object.getOwnPropertySymbols(t);
                    for (a = 0; a < o.length; a++)
                        r = o[a],
                        e.indexOf(r) >= 0 || Object.prototype.propertyIsEnumerable.call(t, r) && (n[r] = t[r])
                }
                return n
            }(e, i);
            return "".concat(t, "?").concat(o.stringify(function(t) {
                for (var e = 1; e < arguments.length; e++) {
                    var r = null != arguments[e] ? arguments[e] : {};
                    e % 2 ? s(Object(r), !0).forEach((function(e) {
                        u(t, e, r[e])
                    }
                    )) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(r)) : s(Object(r)).forEach((function(e) {
                        Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(r, e))
                    }
                    ))
                }
                return t
            }({
                page: r,
                perPage: a,
                sortField: n,
                sortType: l || "DESC"
            }, h)))
        };
        const y = function() {
            var t = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : ""
              , e = t
              , r = e.includes("cocrea.world")
              , a = r ? h.COCREA : h.CCW
              , o = {}
              , i = Boolean(n().get("debugLog"))
              , s = function(t) {
                var n = t.accessKey
                  , s = t.primaryKey
                  , u = t.secondaryKey
                  , h = t.filterKeys
                  , f = void 0 === h ? [] : h
                  , y = t.DBType !== l.USER || r ? s : "".concat(s, "-u")
                  , d = n + y + u + f.toString();
                if (!o[d]) {
                    var C;
                    if (e.includes("cocrea.world")) {
                        var p = f.join(",");
                        C = (0,
                        c.U2)(e + a.get, {
                            params: {
                                accessKey: n,
                                primaryKey: y,
                                secondaryKey: u,
                                filterKeys: p
                            }
                        }).finally((function() {
                            delete o[d]
                        }
                        ))
                    } else
                        C = (0,
                        c.v_)(e + a.get, {
                            accessKey: n,
                            primaryKey: y,
                            secondaryKey: u,
                            filterKeys: f
                        }).finally((function() {
                            delete o[d]
                        }
                        ));
                    return o[d] = C,
                    i && console.log("[cloud DB] new get value request with id: ", o),
                    C
                }
                return i && console.log("[cloud DB]same request is in wait with id:  ", d),
                o[d]
            }
              , u = function(t) {
                var n = t.primaryKey
                  , o = t.secondaryKey
                  , i = t.value
                  , s = {
                    primaryKey: t.DBType !== l.USER || r ? n : "".concat(n, "-u"),
                    secondaryKey: o,
                    value: i
                };
                return (0,
                c.v_)("".concat(e + a.set), s)
            }
              , y = function(t) {
                var n = t.accessKey
                  , o = t.primaryKey
                  , i = t.secondaryKeys
                  , s = t.filterKeys
                  , u = void 0 === s ? [] : s
                  , h = t.DBType !== l.USER || r ? o : "".concat(o, "-u");
                return (0,
                c.v_)(e + a.getList, {
                    accessKey: n,
                    primaryKey: h,
                    secondaryKeys: i,
                    filterKeys: u
                })
            }
              , d = function() {
                var t = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "";
                r = (e = null != t ? t : "").includes("cocrea.world"),
                a = r ? h.COCREA : h.CCW
            }
              , C = function(t) {
                var r = f("".concat(e, "/creation_data_access_config/permission/page"), {
                    page: 1,
                    perPage: 50
                });
                return (0,
                c.v_)(r, {
                    grantedCreationOid: t
                })
            };
            return {
                get: s,
                set: u,
                getList: y,
                setHost: d,
                getConnectedList: C
            }
        }
    }
    ,
    97865: (t, e, r) => {
        r.d(e, {
            U2: () => n,
            v_: () => o
        });
        var a = (0,
        r(7055).create)({
            timeout: 3e4,
            checkApiHostBasedPageRouting: !0,
            environment: "prod",
            apiVersion: "1.1",
            withCredentials: !0
        });
        a.use((function(t, e) {
            e.use((function(t) {
                if (200 != +t.data.status) {
                    var e = t.config
                      , r = e.skipErrorHandler
                      , a = e.skipErrorCodes;
                    r || (void 0 === a ? [] : a).includes(t.data.code) || function(t) {
                        var e = t.data
                          , r = e.code
                          , a = e.msg;
                        throw new Error("Request Error： code: ".concat(r, ", msg: ").concat(a))
                    }(t)
                }
                return t.config.skipTransformResponse ? t.data : t.data.body
            }
            ))
        }
        ));
        var n = a.get
          , o = (a.put,
        a.post);
        a.patch,
        a.delete
    }
    ,
    53818: (t, e, r) => {
        r.r(e),
        r.d(e, {
            default: () => I
        });
        var a = r(98956)
          , n = r(80673)
          , o = r.n(n)
          , c = r(29122)
          , i = r.n(c)
          , s = r(83392)
          , u = r.n(s)
          , l = r(27771)
          , h = r(12960)
          , f = r(19288)
          , y = r(49576)
          , d = r(47285)
          , C = new (r.n(d)());
        C.rule(/"((?:\\"|[^\r\n])*)"/, (function(t, e) {
            t.accept("keyString", e[1])
        }
        )),
        C.rule(/(?<!\.)\.(?!\.)/, (function(t, e) {
            t.accept("getter")
        }
        )),
        C.rule(/\[([0-9]+|['"]([^'"]*)['"])\]/, (function(t, e) {
            void 0 !== e[2] ? t.accept("keyString", e[2]) : t.accept("keyIndex", e[1])
        }
        )),
        C.rule(/[^\[\].]*/, (function(t, e) {
            "" !== e[0].trim() ? t.accept("keyString") : t.reject()
        }
        ));
        const p = C;
        function g(t) {
            return g = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(t) {
                return typeof t
            }
            : function(t) {
                return t && "function" == typeof Symbol && t.constructor === Symbol && t !== Symbol.prototype ? "symbol" : typeof t
            }
            ,
            g(t)
        }
        function v(t, e) {
            var r = Object.keys(t);
            if (Object.getOwnPropertySymbols) {
                var a = Object.getOwnPropertySymbols(t);
                e && (a = a.filter((function(e) {
                    return Object.getOwnPropertyDescriptor(t, e).enumerable
                }
                ))),
                r.push.apply(r, a)
            }
            return r
        }
        function m(t) {
            for (var e = 1; e < arguments.length; e++) {
                var r = null != arguments[e] ? arguments[e] : {};
                e % 2 ? v(Object(r), !0).forEach((function(e) {
                    S(t, e, r[e])
                }
                )) : Object.getOwnPropertyDescriptors ? Object.defineProperties(t, Object.getOwnPropertyDescriptors(r)) : v(Object(r)).forEach((function(e) {
                    Object.defineProperty(t, e, Object.getOwnPropertyDescriptor(r, e))
                }
                ))
            }
            return t
        }
        function D() {
            D = function() {
                return t
            }
            ;
            var t = {}
              , e = Object.prototype
              , r = e.hasOwnProperty
              , a = Object.defineProperty || function(t, e, r) {
                t[e] = r.value
            }
              , n = "function" == typeof Symbol ? Symbol : {}
              , o = n.iterator || "@@iterator"
              , c = n.asyncIterator || "@@asyncIterator"
              , i = n.toStringTag || "@@toStringTag";
            function s(t, e, r) {
                return Object.defineProperty(t, e, {
                    value: r,
                    enumerable: !0,
                    configurable: !0,
                    writable: !0
                }),
                t[e]
            }
            try {
                s({}, "")
            } catch (t) {
                s = function(t, e, r) {
                    return t[e] = r
                }
            }
            function u(t, e, r, n) {
                var o = e && e.prototype instanceof f ? e : f
                  , c = Object.create(o.prototype)
                  , i = new I(n || []);
                return a(c, "_invoke", {
                    value: T(t, r, i)
                }),
                c
            }
            function l(t, e, r) {
                try {
                    return {
                        type: "normal",
                        arg: t.call(e, r)
                    }
                } catch (t) {
                    return {
                        type: "throw",
                        arg: t
                    }
                }
            }
            t.wrap = u;
            var h = {};
            function f() {}
            function y() {}
            function d() {}
            var C = {};
            s(C, o, (function() {
                return this
            }
            ));
            var p = Object.getPrototypeOf
              , v = p && p(p(P([])));
            v && v !== e && r.call(v, o) && (C = v);
            var m = d.prototype = f.prototype = Object.create(C);
            function _(t) {
                ["next", "throw", "return"].forEach((function(e) {
                    s(t, e, (function(t) {
                        return this._invoke(e, t)
                    }
                    ))
                }
                ))
            }
            function O(t, e) {
                function n(a, o, c, i) {
                    var s = l(t[a], t, o);
                    if ("throw" !== s.type) {
                        var u = s.arg
                          , h = u.value;
                        return h && "object" == g(h) && r.call(h, "__await") ? e.resolve(h.__await).then((function(t) {
                            n("next", t, c, i)
                        }
                        ), (function(t) {
                            n("throw", t, c, i)
                        }
                        )) : e.resolve(h).then((function(t) {
                            u.value = t,
                            c(u)
                        }
                        ), (function(t) {
                            return n("throw", t, c, i)
                        }
                        ))
                    }
                    i(s.arg)
                }
                var o;
                a(this, "_invoke", {
                    value: function(t, r) {
                        function a() {
                            return new e((function(e, a) {
                                n(t, r, e, a)
                            }
                            ))
                        }
                        return o = o ? o.then(a, a) : a()
                    }
                })
            }
            function T(t, e, r) {
                var a = "suspendedStart";
                return function(n, o) {
                    if ("executing" === a)
                        throw new Error("Generator is already running");
                    if ("completed" === a) {
                        if ("throw" === n)
                            throw o;
                        return {
                            value: void 0,
                            done: !0
                        }
                    }
                    for (r.method = n,
                    r.arg = o; ; ) {
                        var c = r.delegate;
                        if (c) {
                            var i = S(c, r);
                            if (i) {
                                if (i === h)
                                    continue;
                                return i
                            }
                        }
                        if ("next" === r.method)
                            r.sent = r._sent = r.arg;
                        else if ("throw" === r.method) {
                            if ("suspendedStart" === a)
                                throw a = "completed",
                                r.arg;
                            r.dispatchException(r.arg)
                        } else
                            "return" === r.method && r.abrupt("return", r.arg);
                        a = "executing";
                        var s = l(t, e, r);
                        if ("normal" === s.type) {
                            if (a = r.done ? "completed" : "suspendedYield",
                            s.arg === h)
                                continue;
                            return {
                                value: s.arg,
                                done: r.done
                            }
                        }
                        "throw" === s.type && (a = "completed",
                        r.method = "throw",
                        r.arg = s.arg)
                    }
                }
            }
            function S(t, e) {
                var r = t.iterator[e.method];
                if (void 0 === r) {
                    if (e.delegate = null,
                    "throw" === e.method) {
                        if (t.iterator.return && (e.method = "return",
                        e.arg = void 0,
                        S(t, e),
                        "throw" === e.method))
                            return h;
                        e.method = "throw",
                        e.arg = new TypeError("The iterator does not provide a 'throw' method")
                    }
                    return h
                }
                var a = l(r, t.iterator, e.arg);
                if ("throw" === a.type)
                    return e.method = "throw",
                    e.arg = a.arg,
                    e.delegate = null,
                    h;
                var n = a.arg;
                return n ? n.done ? (e[t.resultName] = n.value,
                e.next = t.nextLoc,
                "return" !== e.method && (e.method = "next",
                e.arg = void 0),
                e.delegate = null,
                h) : n : (e.method = "throw",
                e.arg = new TypeError("iterator result is not an object"),
                e.delegate = null,
                h)
            }
            function E(t) {
                var e = {
                    tryLoc: t[0]
                };
                1 in t && (e.catchLoc = t[1]),
                2 in t && (e.finallyLoc = t[2],
                e.afterLoc = t[3]),
                this.tryEntries.push(e)
            }
            function b(t) {
                var e = t.completion || {};
                e.type = "normal",
                delete e.arg,
                t.completion = e
            }
            function I(t) {
                this.tryEntries = [{
                    tryLoc: "root"
                }],
                t.forEach(E, this),
                this.reset(!0)
            }
            function P(t) {
                if (t) {
                    var e = t[o];
                    if (e)
                        return e.call(t);
                    if ("function" == typeof t.next)
                        return t;
                    if (!isNaN(t.length)) {
                        var a = -1
                          , n = function e() {
                            for (; ++a < t.length; )
                                if (r.call(t, a))
                                    return e.value = t[a],
                                    e.done = !1,
                                    e;
                            return e.value = void 0,
                            e.done = !0,
                            e
                        };
                        return n.next = n
                    }
                }
                return {
                    next: j
                }
            }
            function j() {
                return {
                    value: void 0,
                    done: !0
                }
            }
            return y.prototype = d,
            a(m, "constructor", {
                value: d,
                configurable: !0
            }),
            a(d, "constructor", {
                value: y,
                configurable: !0
            }),
            y.displayName = s(d, i, "GeneratorFunction"),
            t.isGeneratorFunction = function(t) {
                var e = "function" == typeof t && t.constructor;
                return !!e && (e === y || "GeneratorFunction" === (e.displayName || e.name))
            }
            ,
            t.mark = function(t) {
                return Object.setPrototypeOf ? Object.setPrototypeOf(t, d) : (t.__proto__ = d,
                s(t, i, "GeneratorFunction")),
                t.prototype = Object.create(m),
                t
            }
            ,
            t.awrap = function(t) {
                return {
                    __await: t
                }
            }
            ,
            _(O.prototype),
            s(O.prototype, c, (function() {
                return this
            }
            )),
            t.AsyncIterator = O,
            t.async = function(e, r, a, n, o) {
                void 0 === o && (o = Promise);
                var c = new O(u(e, r, a, n),o);
                return t.isGeneratorFunction(r) ? c : c.next().then((function(t) {
                    return t.done ? t.value : c.next()
                }
                ))
            }
            ,
            _(m),
            s(m, i, "Generator"),
            s(m, o, (function() {
                return this
            }
            )),
            s(m, "toString", (function() {
                return "[object Generator]"
            }
            )),
            t.keys = function(t) {
                var e = Object(t)
                  , r = [];
                for (var a in e)
                    r.push(a);
                return r.reverse(),
                function t() {
                    for (; r.length; ) {
                        var a = r.pop();
                        if (a in e)
                            return t.value = a,
                            t.done = !1,
                            t
                    }
                    return t.done = !0,
                    t
                }
            }
            ,
            t.values = P,
            I.prototype = {
                constructor: I,
                reset: function(t) {
                    if (this.prev = 0,
                    this.next = 0,
                    this.sent = this._sent = void 0,
                    this.done = !1,
                    this.delegate = null,
                    this.method = "next",
                    this.arg = void 0,
                    this.tryEntries.forEach(b),
                    !t)
                        for (var e in this)
                            "t" === e.charAt(0) && r.call(this, e) && !isNaN(+e.slice(1)) && (this[e] = void 0)
                },
                stop: function() {
                    this.done = !0;
                    var t = this.tryEntries[0].completion;
                    if ("throw" === t.type)
                        throw t.arg;
                    return this.rval
                },
                dispatchException: function(t) {
                    if (this.done)
                        throw t;
                    var e = this;
                    function a(r, a) {
                        return c.type = "throw",
                        c.arg = t,
                        e.next = r,
                        a && (e.method = "next",
                        e.arg = void 0),
                        !!a
                    }
                    for (var n = this.tryEntries.length - 1; n >= 0; --n) {
                        var o = this.tryEntries[n]
                          , c = o.completion;
                        if ("root" === o.tryLoc)
                            return a("end");
                        if (o.tryLoc <= this.prev) {
                            var i = r.call(o, "catchLoc")
                              , s = r.call(o, "finallyLoc");
                            if (i && s) {
                                if (this.prev < o.catchLoc)
                                    return a(o.catchLoc, !0);
                                if (this.prev < o.finallyLoc)
                                    return a(o.finallyLoc)
                            } else if (i) {
                                if (this.prev < o.catchLoc)
                                    return a(o.catchLoc, !0)
                            } else {
                                if (!s)
                                    throw new Error("try statement without catch or finally");
                                if (this.prev < o.finallyLoc)
                                    return a(o.finallyLoc)
                            }
                        }
                    }
                },
                abrupt: function(t, e) {
                    for (var a = this.tryEntries.length - 1; a >= 0; --a) {
                        var n = this.tryEntries[a];
                        if (n.tryLoc <= this.prev && r.call(n, "finallyLoc") && this.prev < n.finallyLoc) {
                            var o = n;
                            break
                        }
                    }
                    o && ("break" === t || "continue" === t) && o.tryLoc <= e && e <= o.finallyLoc && (o = null);
                    var c = o ? o.completion : {};
                    return c.type = t,
                    c.arg = e,
                    o ? (this.method = "next",
                    this.next = o.finallyLoc,
                    h) : this.complete(c)
                },
                complete: function(t, e) {
                    if ("throw" === t.type)
                        throw t.arg;
                    return "break" === t.type || "continue" === t.type ? this.next = t.arg : "return" === t.type ? (this.rval = this.arg = t.arg,
                    this.method = "return",
                    this.next = "end") : "normal" === t.type && e && (this.next = e),
                    h
                },
                finish: function(t) {
                    for (var e = this.tryEntries.length - 1; e >= 0; --e) {
                        var r = this.tryEntries[e];
                        if (r.finallyLoc === t)
                            return this.complete(r.completion, r.afterLoc),
                            b(r),
                            h
                    }
                },
                catch: function(t) {
                    for (var e = this.tryEntries.length - 1; e >= 0; --e) {
                        var r = this.tryEntries[e];
                        if (r.tryLoc === t) {
                            var a = r.completion;
                            if ("throw" === a.type) {
                                var n = a.arg;
                                b(r)
                            }
                            return n
                        }
                    }
                    throw new Error("illegal catch attempt")
                },
                delegateYield: function(t, e, r) {
                    return this.delegate = {
                        iterator: P(t),
                        resultName: e,
                        nextLoc: r
                    },
                    "next" === this.method && (this.arg = void 0),
                    h
                }
            },
            t
        }
        function _(t, e, r, a, n, o, c) {
            try {
                var i = t[o](c)
                  , s = i.value
            } catch (t) {
                return void r(t)
            }
            i.done ? e(s) : Promise.resolve(s).then(a, n)
        }
        function O(t) {
            return function() {
                var e = this
                  , r = arguments;
                return new Promise((function(a, n) {
                    var o = t.apply(e, r);
                    function c(t) {
                        _(o, a, n, c, i, "next", t)
                    }
                    function i(t) {
                        _(o, a, n, c, i, "throw", t)
                    }
                    c(void 0)
                }
                ))
            }
        }
        function T(t, e) {
            for (var r = 0; r < e.length; r++) {
                var a = e[r];
                a.enumerable = a.enumerable || !1,
                a.configurable = !0,
                "value"in a && (a.writable = !0),
                Object.defineProperty(t, a.key, a)
            }
        }
        function S(t, e, r) {
            return e in t ? Object.defineProperty(t, e, {
                value: r,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : t[e] = r,
            t
        }
        var E = "CCWData.CACHE_POLICY.CACHE_2S"
          , b = "CCWData.CACHE_POLICY.INFINITY"
          , I = function() {
            function t(e) {
                var r = this;
                if (function(t, e) {
                    if (!(t instanceof e))
                        throw new TypeError("Cannot call a class as a function")
                }(this, t),
                S(this, "clearAll", (function() {
                    r._projectCache = {},
                    r._projectCachedTimeout = {},
                    r._projectDataCachePolicy = {},
                    r._userCache = {}
                }
                )),
                S(this, "refreshConnectedList", function() {
                    var t = O(D().mark((function t(e) {
                        var a, n, o, c, i;
                        return D().wrap((function(t) {
                            for (; ; )
                                switch (t.prev = t.next) {
                                case 0:
                                    return t.prev = 0,
                                    r.$reloadBtnTextTag = e.svgGroup_.querySelector(".blocklyText"),
                                    o = 3,
                                    c = r._formatMessage("CCWData.loading"),
                                    r.intervalId = setInterval((function() {
                                        r.$reloadBtnTextTag.textContent = "".concat(c).concat(".".repeat(++o % 4))
                                    }
                                    ), 300),
                                    t.next = 7,
                                    null === (a = r.cloudDB) || void 0 === a ? void 0 : a.getConnectedList(r.projectId);
                                case 7:
                                    i = t.sent,
                                    r.connectedDataBaseList = null === (n = i.data) || void 0 === n ? void 0 : n.filter((function(t) {
                                        var e;
                                        return t.creationOid !== r.projectId && t.creationOid && (null === (e = t.creation) || void 0 === e ? void 0 : e.title)
                                    }
                                    )).map((function(t) {
                                        var e;
                                        return {
                                            text: null === (e = t.creation) || void 0 === e ? void 0 : e.title,
                                            value: t.creationOid
                                        }
                                    }
                                    )),
                                    setTimeout((function() {
                                        clearInterval(r.intervalId),
                                        r.$reloadBtnTextTag.textContent = r._formatMessage("CCWData.loadingFinish"),
                                        setTimeout((function() {
                                            r.$reloadBtnTextTag.textContent = r._formatMessage("CCWData.syncDataBase")
                                        }
                                        ), 2e3)
                                    }
                                    ), 1e3),
                                    t.next = 18;
                                    break;
                                case 12:
                                    t.prev = 12,
                                    t.t0 = t.catch(0),
                                    console.warn("syncDataBase list error", t.t0),
                                    clearInterval(r.intervalId),
                                    r.$reloadBtnTextTag.textContent = r._formatMessage("CCWData.loadingFail"),
                                    r.connectedDataBaseList = null;
                                case 18:
                                case "end":
                                    return t.stop()
                                }
                        }
                        ), t, null, [[0, 12]])
                    }
                    )));
                    return function(e) {
                        return t.apply(this, arguments)
                    }
                }()),
                S(this, "initUUID", O(D().mark((function t() {
                    var e, a;
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                if (!r.runtime.ccwAPI) {
                                    t.next = 7;
                                    break
                                }
                                if (r.runtime.ccwAPI.getProjectUUID && (e = r.runtime.ccwAPI.getProjectUUID(),
                                r.ccwProjectUUID !== e && (r.ccwProjectUUID = e,
                                r._projectCache = {},
                                r._projectCachedTimeout = {},
                                r._projectDataCachePolicy = {}),
                                r.ccwProjectUUID || console.error("CCW API: getProjectUUID return null", r.ccwProjectUUID)),
                                !r.runtime.ccwAPI.getUserInfo) {
                                    t.next = 7;
                                    break
                                }
                                return t.next = 5,
                                r.runtime.ccwAPI.getUserInfo();
                            case 5:
                                (a = t.sent) && r.ccwUserUUID !== a.userId && (r.ccwUserUUID = a.userId,
                                r._userCache = {},
                                r._userValueToBatchPush = {});
                            case 7:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t)
                }
                )))),
                S(this, "sendPlayEventCodeBlock", (function() {
                    return {
                        hideFromPalette: !0,
                        opcode: "sendPlayEventCode",
                        text: r._formatMessage({
                            id: "CCWData.sendPlayEventCode"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            CODE: {
                                type: o().STRING,
                                defaultValue: "code"
                            },
                            DATA: {
                                type: o().STRING,
                                defaultValue: "data"
                            }
                        }
                    }
                }
                )),
                S(this, "setValueBlock", (function() {
                    return {
                        opcode: "setValue",
                        text: r._formatMessage({
                            id: "CCWData.setValue"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: o().STRING,
                                defaultValue: 0
                            }
                        }
                    }
                }
                )),
                S(this, "getValueBlock", (function() {
                    return {
                        opcode: "getValue",
                        text: r._formatMessage({
                            id: "CCWData.getValue"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            }
                        }
                    }
                }
                )),
                S(this, "setValueToDBBlock", (function() {
                    return {
                        opcode: "setValueToDB",
                        text: r._formatMessage({
                            id: "CCWData.setValueToDB"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: o().STRING,
                                defaultValue: 0
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "getValueFromDBBlock", (function() {
                    return {
                        opcode: "getValueFromDB",
                        text: r._formatMessage({
                            id: "CCWData.getValueFromDB"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "getValueListFromDBBlock", (function() {
                    return {
                        opcode: "getValueListFromDB",
                        text: r._formatMessage({
                            id: "CCWData.getValueListFromDB"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY_LIST: {
                                type: o().STRING,
                                menu: "LIST_MENU"
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "getValueListFromDBToListBlock", (function() {
                    return {
                        opcode: "getValueListFromDBToList",
                        text: r._formatMessage({
                            id: "CCWData.getValueListFromDBToList"
                        }),
                        blockType: i().COMMAND,
                        disableMonitor: !0,
                        arguments: {
                            KEY_LIST: {
                                type: o().STRING,
                                menu: "STATIC_LIST_MENU"
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            },
                            TO_LIST: {
                                type: o().STRING,
                                menu: "STATIC_LIST_MENU"
                            }
                        }
                    }
                }
                )),
                S(this, "getValueFromOtherProjectDBBlock", (function() {
                    return {
                        opcode: "getValueFromOtherProjectDB",
                        text: r._formatMessage({
                            id: "CCWData.getValueFromOtherProjectDB"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        hideFromPalette: !0,
                        arguments: {
                            PROJECT_ID: {
                                type: o().STRING,
                                defaultValue: "project_id"
                            },
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "getValueFromOtherProjectDBBlockV2", (function() {
                    return {
                        opcode: "getValueFromOtherProjectDB_V2",
                        text: r._formatMessage({
                            id: "CCWData.getValueFromOtherProjectDB"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            PROJECT_ID: {
                                type: o().STRING,
                                menu: "CONNECTED_LIST"
                            },
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: o().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_isValid", (function() {
                    return {
                        opcode: "isValid",
                        text: r._formatMessage({
                            id: "CCWData.isValid"
                        }),
                        blockType: i().REPORTER,
                        arguments: {
                            VALUE: {
                                type: o().STRING,
                                defaultValue: "[1,2]"
                            },
                            TYPE: {
                                type: o().STRING,
                                defaultValue: "any",
                                menu: "TYPE_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_getValueInJSON", (function() {
                    return {
                        opcode: "getValueInJSON",
                        text: r._formatMessage({
                            id: "CCWData.getValueInJSON"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        hideFromPalette: !0,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            JSON: {
                                type: o().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                S(this, "block_getValueInJSON_2", (function() {
                    return {
                        opcode: "getValueInJSON_2",
                        text: r._formatMessage({
                            id: "CCWData.getValueInJSON_2"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            JSON: {
                                type: o().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                S(this, "block_setValueInJSON", (function() {
                    return {
                        opcode: "setValueInJSON",
                        text: r._formatMessage({
                            id: "CCWData.setValueInJSON"
                        }),
                        blockType: i().REPORTER,
                        hideFromPalette: !0,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: o().STRING,
                                defaultValue: "new value"
                            },
                            JSON: {
                                type: o().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                S(this, "block_setValueInJSON_2", (function() {
                    return {
                        opcode: "setValueInJSON_2",
                        text: r._formatMessage({
                            id: "CCWData.setValueInJSON_2"
                        }),
                        disableMonitor: !0,
                        blockType: i().REPORTER,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: o().STRING,
                                defaultValue: "new value"
                            },
                            JSON: {
                                type: o().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                S(this, "block_fillJSONArrayToList", (function() {
                    return {
                        opcode: "fillJSONArrayToList",
                        text: r._formatMessage({
                            id: "CCWData.fillJSONArrayToList"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            JSON: {
                                type: o().STRING,
                                defaultValue: "[1,2,3]"
                            },
                            LIST: {
                                type: o().STRING,
                                menu: "LIST_MENU"
                            },
                            METHOD: {
                                type: o().STRING,
                                defaultValue: "replace",
                                menu: "METHOD_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_getJSONArrayFromList", (function() {
                    return {
                        opcode: "getJSONArrayFromList",
                        text: r._formatMessage({
                            id: "CCWData.getJSONArrayFromList"
                        }),
                        blockType: i().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            LIST: {
                                type: o().STRING,
                                menu: "LIST_MENU"
                            },
                            METHOD: {
                                type: o().STRING,
                                defaultValue: "convert",
                                menu: "PARSE_METHOD_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_setProjectDataCachePolicy", (function() {
                    return {
                        opcode: "setProjectDataCachePolicy",
                        text: r._formatMessage({
                            id: "CCWData.setProjectDataCachePolicy"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            KEY: {
                                type: o().STRING,
                                defaultValue: "key"
                            },
                            CACHE: {
                                type: o().STRING,
                                defaultValue: E,
                                menu: "CACHE_POLICY_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_setProjectDataCachePolicyByBatch", (function() {
                    return {
                        opcode: "setProjectDataCachePolicyByBatch",
                        text: r._formatMessage({
                            id: "CCWData.setProjectDataCachePolicyByBatch"
                        }),
                        blockType: i().COMMAND,
                        arguments: {
                            KEYS_STR: {
                                type: o().STRING,
                                defaultValue: "key1,key2,key3"
                            },
                            CACHE: {
                                type: o().STRING,
                                defaultValue: E,
                                menu: "CACHE_POLICY_LIST"
                            }
                        }
                    }
                }
                )),
                S(this, "block_getAllProjectDataCachePolicy", (function() {
                    return {
                        text: r._formatMessage({
                            id: "CCWData.getAllProjectDataCachePolicy"
                        }),
                        blockType: i().BUTTON,
                        onClick: function() {
                            var t = Object.keys(r._projectDataCachePolicy);
                            r.runtime.logSystem.show(),
                            0 === t.length ? r.runtime.logSystem.info("[CCWData]No custom cache policy, all use default 2s cache policy") : (r.runtime.logSystem.info("[CCWData] --- CCWData Cache Policy ---"),
                            t.forEach((function(t) {
                                r.runtime.logSystem.info("[CCWData] ".concat(t.split("-")[1], " : ").concat(r._formatMessage(r._projectDataCachePolicy[t])))
                            }
                            )))
                        }
                    }
                }
                )),
                S(this, "block_resetAllProjectDataCachePolicy", (function() {
                    return {
                        text: r._formatMessage({
                            id: "CCWData.resetAllProjectDataCachePolicy"
                        }),
                        blockType: i().BUTTON,
                        onClick: function() {
                            Object.keys(r._projectDataCachePolicy).forEach((function(t) {
                                r._clearProjectCache(t),
                                delete r._projectDataCachePolicy[t]
                            }
                            ))
                        }
                    }
                }
                )),
                S(this, "block_getConnectedDataBase", (function() {
                    return {
                        text: r._formatMessage({
                            id: "CCWData.syncDataBase"
                        }),
                        blockType: i().BUTTON,
                        onClick: r.refreshConnectedList
                    }
                }
                )),
                S(this, "_getConnectedList", (function() {
                    return r.connectedDataBaseList && 0 !== r.connectedDataBaseList.length ? r.connectedDataBaseList : [{
                        text: r._formatMessage({
                            id: "CCWData.syncDataBaseTip"
                        }),
                        value: "-"
                    }]
                }
                )),
                S(this, "_getAllVariablesList", (function() {
                    var t = []
                      , e = r.runtime._stageTarget.variables;
                    Object.keys(e).forEach((function(r) {
                        "" === e[r].type && t.push({
                            text: "".concat(e[r].name),
                            value: e[r].id
                        })
                    }
                    ));
                    var a = r.runtime._editingTarget.variables;
                    return Object.keys(a).forEach((function(e) {
                        "" === a[e].type && t.push({
                            text: "*私有变量*".concat(a[e].name),
                            value: a[e].id
                        })
                    }
                    )),
                    0 === t.length && t.push({
                        text: "*请先创建变量*",
                        value: "empty"
                    }),
                    t
                }
                )),
                S(this, "_getAllDBList", (function() {
                    return [{
                        text: r._formatMessage({
                            id: "CCWData.user",
                            default: "user data"
                        }),
                        value: h.w.USER
                    }, {
                        text: r._formatMessage({
                            id: "CCWData.project",
                            default: "project data"
                        }),
                        value: h.w.PROJECT
                    }]
                }
                )),
                S(this, "_getCacheKey", (function(t) {
                    return "".concat(r.projectId, "-").concat(t)
                }
                )),
                S(this, "_clearProjectCache", (function(t) {
                    delete r._projectCache[t],
                    delete r._projectCachedTimeout[t]
                }
                )),
                S(this, "_setProjectDataCachePolicy", (function(t, e) {
                    r._clearProjectCache(t),
                    r._projectDataCachePolicy[t] = e
                }
                )),
                S(this, "_refreshProjectCacheTimeout", (function(t) {
                    var e = r._projectCachedTimeout[t];
                    if (e && clearTimeout(e),
                    r._projectDataCachePolicy[t] !== b) {
                        var a = setTimeout((function() {
                            r._clearProjectCache(t)
                        }
                        ), 2e3);
                        r._projectCachedTimeout[t] = a
                    }
                }
                )),
                S(this, "_batchSetValuesToUser", (0,
                a.Z)(O(D().mark((function t() {
                    var e, a;
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                if (null === (e = r.runtime.ccwAPI) || void 0 === e || !e.preActionInterceptor) {
                                    t.next = 3;
                                    break
                                }
                                return t.next = 3,
                                r.runtime.ccwAPI.preActionInterceptor();
                            case 3:
                                null === (a = r.cloudDB) || void 0 === a || a.set({
                                    primaryKey: r.projectId,
                                    secondaryKey: r.UserId,
                                    value: r._userValueToBatchPush,
                                    DBType: h.w.USER
                                }).then((function() {
                                    r._userValueToBatchPush = {}
                                }
                                ));
                            case 4:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t)
                }
                ))), 1500)),
                this._formatMessage = e.getFormatMessage({
                    "zh-cn": {
                        "CCWData.name": "Gandi云数据",
                        "CCWData.user": "用户数据库",
                        "CCWData.project": "作品数据库",
                        "CCWData.setValue": "☁ 保存[KEY]=[VALUE]",
                        "CCWData.getValue": "☁ 读取[KEY]",
                        "CCWData.setValueToDB": "☁ 将[VALUE]命名为[KEY]保存到[DB]",
                        "CCWData.getValueFromDB": "☁ 从当前作品的[DB]读取名为[KEY]的值",
                        "CCWData.div.cloud": "☁ 云端数据库",
                        "CCWData.div.json": "⚙ JSON 工具",
                        "CCWData.div.batch": "📦 批量读取 - 最大支持50条每次",
                        "CCWData.div.cache": "💾 缓存策略",
                        "CCWData.getValueListFromDBToList": "📦 批量读取-从当前作品的[DB]批量读取[KEY_LIST]中的值，并赋值到列表[TO_LIST]",
                        "CCWData.getValueListFromDB": "📦 批量读取-从当前作品的[DB]批量读取[KEY_LIST]中的值",
                        "CCWData.getValueListFromDB.MAX": "📦 批量读取-列表长度超长，最多支持50个",
                        "CCWData.getValueFromOtherProjectDB": "☁ 从作品[PROJECT_ID]的[DB]读取名为[KEY]的值",
                        "CCWData.setProjectDataCachePolicy": "设置作品数据库的[KEY]的缓存策略为[CACHE]",
                        "CCWData.setProjectDataCachePolicyByBatch": "📦 批量设置-设置作品数据的[KEYS_STR]的缓存策略为[CACHE]",
                        "CCWData.getAllProjectDataCachePolicy": "🖨️ 打印所有自定义缓存策略",
                        "CCWData.resetAllProjectDataCachePolicy": "⚠️ 重置所有所有自定义缓存策略",
                        "CCWData.CACHE_POLICY.NO_CACHE": "不缓存",
                        "CCWData.CACHE_POLICY.CACHE_2S": "缓存2秒",
                        "CCWData.CACHE_POLICY.INFINITY": "永久缓存",
                        "CCWData.sendPlayEventCode": "发送日志Code =[CODE]data =[DATA]",
                        "CCWData.getValueInJSON": "（❌ 过时的方法）获得[KEY]在[JSON]中的值",
                        "CCWData.getValueInJSON_2": "获得[KEY]在[JSON]中的值",
                        "CCWData.isValid": "[VALUE] 是合法的 [TYPE]?",
                        "CCWData.isObjectOrArray": "对象或数组",
                        "CCWData.isObject": "对象",
                        "CCWData.isArray": "数组",
                        "CCWData.setValueInJSON": "（❌ 过时的方法）设置[JSON]中的[KEY]的值为[VALUE]",
                        "CCWData.setValueInJSON_2": "设置[JSON]中的[KEY]的值为[VALUE]",
                        "CCWData.fillJSONArrayToList": "把 [JSON] [METHOD] 列表 [LIST]",
                        "CCWData.replace": "覆盖",
                        "CCWData.insert": "插入",
                        "CCWData.getJSONArrayFromList": "转化 [LIST] 到 JSON，并且对其中的值 [METHOD]",
                        "CCWData.convert": "尝试转化成对象",
                        "CCWData.skip": "不转化",
                        "CCWData.div.connection": "🌐 数据互联",
                        "CCWData.syncDataBase": "同步互联数据库菜单",
                        "CCWData.syncDataBaseTip": "没有互联数据库，尝试[同步按钮]",
                        "CCWData.loading": "同步中...",
                        "CCWData.loadingFail": "❌ 同步失败，请重试",
                        "CCWData.loadingFinish": "✅ 同步完成"
                    },
                    en: {
                        "CCWData.name": "Gandi Cloud Data",
                        "CCWData.user": "user data",
                        "CCWData.project": "project data",
                        "CCWData.setValue": "☁ save [KEY]=[VALUE]",
                        "CCWData.getValue": "☁ read [KEY] value",
                        "CCWData.setValueToDB": "☁ set [VALUE] to [KEY] in [DB]",
                        "CCWData.getValueFromDB": "☁ read [KEY] from current [DB]",
                        "CCWData.getValueFromOtherProjectDB": "☁ read [KEY] from project [PROJECT_ID][DB]",
                        "CCWData.div.cloud": "☁ Cloud Database",
                        "CCWData.div.json": "⚙ JSON Utils",
                        "CCWData.div.batch": "📦 Read in Batches - max 50 keys in one batch",
                        "CCWData.div.cache": "💾 Cache Policy",
                        "CCWData.getValueListFromDBToList": "📦 read in batches - all value which key in [KEY_LIST] from current [DB] and set to list [TO_LIST]",
                        "CCWData.getValueListFromDB": "📦 read in batches - all value which key in [KEY_LIST] from current [DB]",
                        "CCWData.getValueListFromDB.MAX": "📦 read in batches - list length overrange, max length is 50",
                        "CCWData.sendPlayEventCode": "☁ send event code =[CODE]data =[DATA]",
                        "CCWData.setProjectDataCachePolicy": "set cache policy of [KEY] in project data to [CACHE]",
                        "CCWData.setProjectDataCachePolicyByBatch": "📦 batch set cache policy of [KEYS_STR] in project data to [CACHE]",
                        "CCWData.getAllProjectDataCachePolicy": "🖨️ print all custom cache policy",
                        "CCWData.resetAllProjectDataCachePolicy": "⚠️ reset all custom cache policy",
                        "CCWData.CACHE_POLICY.NO_CACHE": "no cache",
                        "CCWData.CACHE_POLICY.CACHE_2S": "cache 2s",
                        "CCWData.CACHE_POLICY.INFINITY": "cache forever",
                        "CCWData.getValueInJSON": "(❌ DEPRECATED)get [KEY] in [JSON]",
                        "CCWData.getValueInJSON_2": "get [KEY] in [JSON]",
                        "CCWData.isValid": "[VALUE] is a valid [TYPE]?",
                        "CCWData.isObjectOrArray": "object or array",
                        "CCWData.isObject": "object",
                        "CCWData.isArray": "array",
                        "CCWData.setValueInJSON": "(❌ DEPRECATED)set [VALUE] of key [KEY] in [JSON]",
                        "CCWData.setValueInJSON_2": "set [VALUE] of key [KEY] in [JSON]",
                        "CCWData.fillJSONArrayToList": "[METHOD] [LIST] with [JSON]",
                        "CCWData.replace": "replace",
                        "CCWData.insert": "insert",
                        "CCWData.getJSONArrayFromList": "parse [LIST] to JSON and [METHOD]",
                        "CCWData.convert": "try converting values to object",
                        "CCWData.skip": "do not convert values",
                        "CCWData.div.connection": "🌐 Connection",
                        "CCWData.syncDataBase": "Sync DataBase Menu",
                        "CCWData.syncDataBaseTip": "No DataBase, try [Sync Button]",
                        "CCWData.loading": "Syncing...",
                        "CCWData.loadingFail": "❌ Sync Failed, try again",
                        "CCWData.loadingFinish": "✅ Sync Finished"
                    }
                }),
                this._projectCache = {},
                this._projectCachedTimeout = {},
                this._projectDataCachePolicy = {},
                this._userCache = {},
                this._userValueToBatchPush = {},
                this._backupValueCache = {},
                this.runtime = e,
                e.ccwAPI && e.ccwAPI.getOnlineExtensionsConfig) {
                    var n = e.ccwAPI.getOnlineExtensionsConfig().hosts;
                    n && n.cloudDBHost && (this.host = n.cloudDBHost)
                }
                this.host ? (this.cloudDB = (0,
                h.Z)(this.host),
                this.runtime.on("PROJECT_STOP_ALL", (function() {
                    r.clearAll()
                }
                )),
                this.runtime.on("CCWAPI_CHANGED", (function() {
                    r.initUUID()
                }
                )),
                this.initUUID()) : console.warn("CCWData: host is not provided, stop init")
            }
            var e, r, n, c, s, d;
            return e = t,
            r = [{
                key: "getInfo",
                value: function() {
                    return {
                        id: "CCWData",
                        name: this._formatMessage({
                            id: "CCWData.name",
                            default: "CCWData"
                        }),
                        color1: "#ED35A3",
                        menuIconURI: f.Z,
                        blockIconURI: f.Z,
                        blocks: ["---".concat(this._formatMessage({
                            id: "CCWData.div.cloud",
                            default: "☁️ Cloud Data"
                        })), this.setValueToDBBlock(), this.getValueFromDBBlock(), "---".concat(this._formatMessage({
                            id: "CCWData.div.connection"
                        })), this.block_getConnectedDataBase(), this.getValueFromOtherProjectDBBlock(), this.getValueFromOtherProjectDBBlockV2(), this.sendPlayEventCodeBlock(), "---".concat(this._formatMessage({
                            id: "CCWData.div.batch",
                            default: "📦 Read in Batches - max 50 keys in one batch"
                        })), this.getValueListFromDBBlock(), this.getValueListFromDBToListBlock(), "---".concat(this._formatMessage({
                            id: "CCWData.div.json",
                            default: "🏷 JSON Utils"
                        })), this.block_isValid(), this.block_getValueInJSON(), this.block_setValueInJSON(), this.block_getValueInJSON_2(), this.block_setValueInJSON_2(), this.block_fillJSONArrayToList(), this.block_getJSONArrayFromList(), "---".concat(this._formatMessage({
                            id: "CCWData.div.cache",
                            default: "⚙️ Cache Policy"
                        })), this.block_setProjectDataCachePolicy(), this.block_setProjectDataCachePolicyByBatch(), this.block_getAllProjectDataCachePolicy(), this.block_resetAllProjectDataCachePolicy()],
                        menus: {
                            CONNECTED_LIST: {
                                items: "_getConnectedList"
                            },
                            VAR_LIST: {
                                items: "_getAllVariablesList"
                            },
                            DB_LIST: {
                                items: "_getAllDBList"
                            },
                            TYPE_LIST: [{
                                text: this._formatMessage("CCWData.isObject"),
                                value: "object"
                            }, {
                                text: this._formatMessage("CCWData.isArray"),
                                value: "array"
                            }, {
                                text: this._formatMessage("CCWData.isObjectOrArray"),
                                value: "any"
                            }],
                            LIST_MENU: {
                                acceptReporters: !0,
                                items: "findAllList"
                            },
                            STATIC_LIST_MENU: {
                                acceptReporters: !1,
                                items: "findAllList"
                            },
                            METHOD_LIST: [{
                                text: this._formatMessage("CCWData.replace"),
                                value: "replace"
                            }, {
                                text: this._formatMessage("CCWData.insert"),
                                value: "insert"
                            }],
                            PARSE_METHOD_LIST: [{
                                text: this._formatMessage("CCWData.convert"),
                                value: "convert"
                            }, {
                                text: this._formatMessage("CCWData.skip"),
                                value: "skip"
                            }],
                            CACHE_POLICY_LIST: [{
                                text: this._formatMessage(b),
                                value: b
                            }, {
                                text: this._formatMessage(E),
                                value: E
                            }]
                        }
                    }
                }
            }, {
                key: "projectId",
                get: function() {
                    return this.ccwProjectUUID || (this.ccwProjectUUID = this.runtime.ccwAPI.getProjectUUID(),
                    this.ccwProjectUUID || console.error("CCW API: getProjectUUID return null", this.ccwProjectUUID)),
                    this.ccwProjectUUID
                }
            }, {
                key: "UserId",
                get: function() {
                    return this.ccwUserUUID ? this.ccwUserUUID : (this.initUUID(),
                    "CCW_anonymous".concat((new Date).getTime()))
                }
            }, {
                key: "_setValueToProject",
                value: (d = O(D().mark((function t(e, r) {
                    var a, n, o;
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                if (a = this._getCacheKey(e),
                                this._projectCache[a] === r) {
                                    t.next = 8;
                                    break
                                }
                                if (this._projectCache[a] = r,
                                this._refreshProjectCacheTimeout(a),
                                null === (n = this.runtime.ccwAPI) || void 0 === n || !n.preActionInterceptor) {
                                    t.next = 7;
                                    break
                                }
                                return t.next = 7,
                                this.runtime.ccwAPI.preActionInterceptor();
                            case 7:
                                return t.abrupt("return", null === (o = this.cloudDB) || void 0 === o ? void 0 : o.set({
                                    primaryKey: this.projectId,
                                    secondaryKey: e,
                                    value: {
                                        v: r
                                    },
                                    DBType: h.w.PROJECT
                                }));
                            case 8:
                                return t.abrupt("return", Promise.resolve("value not changed"));
                            case 9:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t, this)
                }
                ))),
                function(t, e) {
                    return d.apply(this, arguments)
                }
                )
            }, {
                key: "_getValueFromProject",
                value: function(t) {
                    var e, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = "".concat(a, "-").concat(t);
                    return Object.prototype.hasOwnProperty.call(this._projectCache, n) ? this._projectCache[n] : null === (e = this.cloudDB) || void 0 === e ? void 0 : e.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: t,
                        DBType: h.w.PROJECT
                    }).then((function(t) {
                        return r._projectCache[n] = t.v || "",
                        r._refreshProjectCacheTimeout(n),
                        r._projectCache[n]
                    }
                    ))
                }
            }, {
                key: "_getListValueFromProject",
                value: function(t) {
                    var e, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = [], o = [], c = "ccw_loading_";
                    return t.forEach((function(t) {
                        var e = "".concat(a, "-").concat(t);
                        r._projectCache[e] && r._projectCachedTimeout[e] ? n.push(r._projectCache[e]) : (n.push(c + t),
                        o.push(t))
                    }
                    )),
                    o.length > 0 ? null === (e = this.cloudDB) || void 0 === e ? void 0 : e.getList({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKeys: o,
                        DBType: h.w.PROJECT
                    }).then((function(t) {
                        return t ? n.map((function(e) {
                            if (e.startsWith(c)) {
                                var n = e.replace(c, "")
                                  , o = "".concat(a, "-").concat(n)
                                  , i = t[n].v;
                                return r._projectCache[o] = i,
                                r._refreshProjectCacheTimeout(o),
                                i
                            }
                            return e
                        }
                        )) : null
                    }
                    )) : n
                }
            }, {
                key: "_setValueToUser",
                value: function(t, e) {
                    var r = this._getCacheKey(t);
                    this._userCache[r] !== e && (this._userCache[r] = e,
                    this._userValueToBatchPush[t] = e,
                    this._batchSetValuesToUser())
                }
            }, {
                key: "_getValueFromUser",
                value: function(t) {
                    var e, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = "".concat(a, "-").concat(t);
                    return Object.prototype.hasOwnProperty.call(this._userCache, n) ? this._userCache[n] : null === (e = this.cloudDB) || void 0 === e ? void 0 : e.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: this.UserId,
                        filterKeys: [t],
                        DBType: h.w.USER
                    }).then((function(e) {
                        return r._userCache[n] = e[t] || "",
                        r._userCache[n]
                    }
                    ))
                }
            }, {
                key: "_getValueListFromUser",
                value: function(t) {
                    var e, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = [], o = [], c = "ccw_loading_";
                    return t.forEach((function(t) {
                        var e = "".concat(a, "-").concat(t);
                        r._userCache[e] && r._projectCachedTimeout[e] ? n.push(r._userCache[e]) : (n.push(c + t),
                        o.push(t))
                    }
                    )),
                    o.length > 0 ? null === (e = this.cloudDB) || void 0 === e ? void 0 : e.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: this.UserId,
                        filterKeys: o,
                        DBType: h.w.USER
                    }).then((function(t) {
                        return t ? n.map((function(e) {
                            if (e.startsWith(c)) {
                                var n = e.replace(c, "")
                                  , o = "".concat(a, "-").concat(n);
                                if (Object.prototype.hasOwnProperty.call(t, n)) {
                                    var i = t[n];
                                    return r._userCache[o] = i,
                                    r._refreshProjectCacheTimeout(o),
                                    i
                                }
                                return ""
                            }
                            return e
                        }
                        )) : null
                    }
                    )) : n
                }
            }, {
                key: "setValueToDB",
                value: function(t) {
                    var e = u().toString(t.KEY)
                      , r = u().toString(t.VALUE);
                    t.DB === h.w.USER ? this._setValueToUser(e, r) : t.DB === h.w.PROJECT && this._setValueToProject(e, r)
                }
            }, {
                key: "getValueFromDB",
                value: function(t) {
                    var e = t.KEY
                      , r = t.DB
                      , a = u().toString(e);
                    return r === h.w.USER ? this._getValueFromUser(a) : r === h.w.PROJECT ? this._getValueFromProject(a) : ""
                }
            }, {
                key: "getValueFromOtherProjectDB",
                value: function(t) {
                    var e = u().toString(t.KEY)
                      , r = u().toString(t.PROJECT_ID);
                    return t.DB === h.w.USER ? this._getValueFromUser(e, r) : t.DB === h.w.PROJECT ? this._getValueFromProject(e, r) : ""
                }
            }, {
                key: "_generateBackupKey",
                value: function(t, e) {
                    return "backup_".concat(t, "_").concat(e)
                }
            }, {
                key: "_getBackUpValueFromOtherProjectDB",
                value: function(t) {
                    var e = t.PROJECT_ID
                      , r = t.KEY
                      , a = t.DB
                      , n = this._generateBackupKey(e, r);
                    return this.getValueFromDB({
                        KEY: n,
                        DB: a
                    })
                }
            }, {
                key: "_setBackUpValueWhenReadFromOtherProjectDB",
                value: function(t) {
                    var e = t.PROJECT_ID
                      , r = t.KEY
                      , a = t.VALUE
                      , n = t.DB
                      , o = this._generateBackupKey(e, r)
                      , c = o + (n === h.w.USER ? "-u" : "-p");
                    this._backupValueCache[c] !== a && (this._backupValueCache[c] = a,
                    this.setValueToDB({
                        KEY: o,
                        VALUE: a,
                        DB: n
                    }))
                }
            }, {
                key: "getValueFromOtherProjectDB_V2",
                value: (s = O(D().mark((function t(e) {
                    var r;
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                return t.prev = 0,
                                t.next = 3,
                                this.getValueFromOtherProjectDB(e);
                            case 3:
                                return (r = t.sent) && this._setBackUpValueWhenReadFromOtherProjectDB(m(m({}, e), {}, {
                                    VALUE: r
                                })),
                                t.abrupt("return", r);
                            case 8:
                                return t.prev = 8,
                                t.t0 = t.catch(0),
                                t.abrupt("return", this.__getBackUpValueFromOtherProjectDB_V2(e));
                            case 11:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t, this, [[0, 8]])
                }
                ))),
                function(t) {
                    return s.apply(this, arguments)
                }
                )
            }, {
                key: "_getValueListFromDB",
                value: (c = O(D().mark((function t(e, r) {
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                if (r !== h.w.USER) {
                                    t.next = 2;
                                    break
                                }
                                return t.abrupt("return", this._getValueListFromUser(e));
                            case 2:
                                if (r !== h.w.PROJECT) {
                                    t.next = 7;
                                    break
                                }
                                if (!(e.length > 50)) {
                                    t.next = 6;
                                    break
                                }
                                return this.runtime.logSystem.error(this._formatMessage("CCWData.getValueListFromDB.MAX")),
                                t.abrupt("return", this._formatMessage("CCWData.getValueListFromDB.MAX"));
                            case 6:
                                return t.abrupt("return", this._getListValueFromProject(e));
                            case 7:
                                return t.abrupt("return", null);
                            case 8:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t, this)
                }
                ))),
                function(t, e) {
                    return c.apply(this, arguments)
                }
                )
            }, {
                key: "getValueListFromDB",
                value: (n = O(D().mark((function t(e, r) {
                    var a, n, o;
                    return D().wrap((function(t) {
                        for (; ; )
                            switch (t.prev = t.next) {
                            case 0:
                                if (a = e.KEY_LIST,
                                n = e.DB,
                                o = this.lookupListByIdOrName(a, r)) {
                                    t.next = 5;
                                    break
                                }
                                return console.warn("[CCWData]⚠️ Get value list from DB: source list not found"),
                                t.abrupt("return", "");
                            case 5:
                                return t.abrupt("return", this._getValueListFromDB(o.value, n).then((function(t) {
                                    return Array.isArray(t) ? t.join(",") : null != t ? t : ""
                                }
                                )));
                            case 6:
                            case "end":
                                return t.stop()
                            }
                    }
                    ), t, this)
                }
                ))),
                function(t, e) {
                    return n.apply(this, arguments)
                }
                )
            }, {
                key: "getValueListFromDBToList",
                value: function(t, e) {
                    var r = t.TO_LIST;
                    !r && t && t.LIST && "object" === g(t.LIST) && t.LIST.id && (r = t.LIST.id);
                    var a = this.lookupListByIdOrName(r, e);
                    if (a) {
                        var n = this.lookupListByIdOrName(t.KEY_LIST, e);
                        if (n)
                            return this._getValueListFromDB(n.value, t.DB).then((function(t) {
                                Array.isArray(t) && (a.value = t)
                            }
                            ));
                        console.warn("[CCWData]⚠️ Get value list from DB: source list not found")
                    } else
                        console.warn("[CCWData]⚠️ Get value list from DB: list to fill not found")
                }
            }, {
                key: "sendPlayEventCode",
                value: function(t) {
                    this.runtime.ccwAPI.sendPlayEventCode([8592293917, 1], {
                        code: t.CODE,
                        data: t.DATA
                    })
                }
            }, {
                key: "isValid",
                value: function(t) {
                    var e = u().toString(t.VALUE)
                      , r = u().toString(t.TYPE);
                    try {
                        var a = JSON.parse(e);
                        if (null === a)
                            return !1;
                        if ("any" === r)
                            return !0;
                        if ("object" === r)
                            return !Array.isArray(a);
                        if ("array" === r)
                            return Array.isArray(a)
                    } catch (t) {
                        return !1
                    }
                    return !1
                }
            }, {
                key: "getValueInJSON",
                value: function(t) {
                    var e, r = u().toString(t.KEY), a = u().toString(t.JSON);
                    try {
                        e = JSON.parse(a)
                    } catch (t) {
                        return "error: ".concat(t.message)
                    }
                    if (/[()=]/gm.test(r))
                        return "error: invalid key ".concat(r, ", cannot contain ()=");
                    var n, o = "jsonObj[".concat(r, "]");
                    Array.isArray(e) ? r = r.startsWith("[") ? "jsonObj".concat(r) : "jsonObj[".concat(r, "]") : /\s/gm.test(r) ? (console.warn("[CCW Data] warning: invalid key ".concat(r, ", space and dot cannot be used together")),
                    r = 'jsonObj["'.concat(r, '"]')) : r = "jsonObj.".concat(r);
                    try {
                        n = (0,
                        y.Br)("return ".concat(r), {
                            jsonObj: e
                        })
                    } catch (t) {
                        try {
                            n = (0,
                            y.Br)("return ".concat(o), {
                                jsonObj: e
                            })
                        } catch (t) {
                            return "error: key or expression invalid"
                        }
                    }
                    return "object" === g(n) ? JSON.stringify(n) : n
                }
            }, {
                key: "_findValueByKeyString",
                value: function(t, e) {
                    var r = ""
                      , a = t;
                    return p.input(e),
                    p.tokens().forEach((function(t) {
                        if ("getter" !== t.type && "EOF" !== t.type)
                            try {
                                a = a["".concat(t.value)],
                                r += "[".concat(t.value, "]")
                            } catch (e) {
                                throw new Error("cannot find key '".concat(t.value, "', current Object").concat(r, " is '").concat(JSON.stringify(a), "'"))
                            }
                    }
                    )),
                    a
                }
            }, {
                key: "_logError",
                value: function(t, e) {
                    var r = this._formatMessage({
                        id: "CCWData.name",
                        default: "CCWData"
                    });
                    if (t) {
                        var a = this._formatMessage({
                            id: t
                        });
                        r = "".concat(r, "-").concat(a)
                    }
                    this.runtime.logSystem.error("Error:".concat(r, "\n  ").concat(e))
                }
            }, {
                key: "getValueInJSON_2",
                value: function(t) {
                    var e = u().toString(t.KEY)
                      , r = u().toString(t.JSON);
                    try {
                        var a = JSON.parse(r)
                          , n = this._findValueByKeyString(a, e);
                        return "object" === g(n) ? JSON.stringify(n) : n
                    } catch (t) {
                        return this._logError("CCWData.getValueInJSON_2", t.toString()),
                        "error: ".concat(t.message)
                    }
                }
            }, {
                key: "setValueInJSON",
                value: function(t) {
                    var e, r = u().toString(t.KEY), a = u().toString(t.VALUE), n = u().toString(t.JSON);
                    try {
                        e = JSON.parse(n)
                    } catch (t) {
                        return "error: ".concat(t.message)
                    }
                    if (/[()=]/gm.test(r))
                        return "error: invalid key ".concat(r, ", cannot contain ()=");
                    var o = a;
                    if (/^[\[].*?[\]]$/gm.test(a) || /^[\{].*?[\}]$/gm.test(a))
                        try {
                            o = JSON.parse(a)
                        } catch (t) {}
                    "string" == typeof o && /^-?\d*\.?\d*$/gm.test(o) && (o = Number(o));
                    try {
                        Array.isArray(e) ? e[r] = o : /[\.\[\]]/gm.test(r) ? (0,
                        y.Br)("jsonObj.".concat(r, " = valueObj;"), {
                            jsonObj: e,
                            valueObj: o
                        }) : e[r] = o
                    } catch (t) {
                        return "error: key or expression invalid"
                    }
                    return JSON.stringify(e)
                }
            }, {
                key: "setValueInJSON_2",
                value: function(t) {
                    var e, r = u().toString(t.KEY), a = u().toString(t.VALUE), n = u().toString(t.JSON);
                    try {
                        e = JSON.parse(n)
                    } catch (t) {
                        return "error: ".concat(t.message)
                    }
                    if (/[()=]/gm.test(r))
                        return "error: invalid key ".concat(r, ", cannot contain ()=");
                    var o = a;
                    if (/^[\[].*?[\]]$/gm.test(a) || /^[\{].*?[\}]$/gm.test(a))
                        try {
                            o = JSON.parse(a)
                        } catch (t) {}
                    "string" == typeof o && /^-?\d*\.?\d*$/gm.test(o) && (o = Number(o));
                    var c = ""
                      , i = e;
                    p.input(r);
                    try {
                        return p.tokens().forEach((function(t, e, r) {
                            if ("getter" !== t.type && "EOF" !== t.type)
                                if (c += "[".concat(t.value, "]"),
                                e !== r.length - 2) {
                                    if (!i)
                                        throw new Error("cannot set value for key '".concat(t.value, "', current Object").concat(c, " is 'undefined'"));
                                    i = i[t.value]
                                } else {
                                    if ((0,
                                    l.Z)(i) && Number.isNaN(t.value))
                                        throw new Error("cannot set value for key '".concat(t.value, "', current Object").concat(c, " is an array, use index instead"));
                                    i[t.value] = o
                                }
                        }
                        )),
                        JSON.stringify(e)
                    } catch (t) {
                        return this._logError("CCWData.setValueInJSON_2", t.toString()),
                        "error: ".concat(t.message)
                    }
                }
            }, {
                key: "lookupListByIdOrName",
                value: function(t, e) {
                    var r = e.target.lookupVariableById(t) || e.target.lookupVariableByNameAndType(t, "list");
                    if (!r) {
                        var a = e.stackFrame.globalTarget;
                        if (!a)
                            return null;
                        var n = a.lookupVariableById(t) || a.lookupVariableByNameAndType(t, "list");
                        if (n) {
                            var o = e.target.isStage ? "Stage: ".concat(n.name) : n.name;
                            r = e.target.lookupOrCreateList((0,
                            y.sq)(), o)
                        }
                    }
                    return r
                }
            }, {
                key: "fillJSONArrayToList",
                value: function(t, e) {
                    var r, a = u().toString(t.JSON);
                    if ("empty" !== t.LIST) {
                        try {
                            r = JSON.parse(a)
                        } catch (t) {
                            return void console.warn("[CCWData]⚠️ fill list: invalid JSON String ".concat(t.message))
                        }
                        if (Array.isArray(r)) {
                            try {
                                r = r.map((function(t) {
                                    return t instanceof Object ? JSON.stringify(t) : t
                                }
                                ))
                            } catch (t) {
                                return void console.warn("[CCWData]⚠️ fill list: JSON Array cannot be converted to string ".concat(t.message))
                            }
                            var n = this.lookupListByIdOrName(t.LIST, e);
                            if (n) {
                                var o = [];
                                "insert" === t.METHOD && (o = o.concat(n.value)),
                                n.value = o.concat(r)
                            } else
                                console.warn("[CCWData]⚠️ fill list: list not found")
                        } else
                            console.warn("[CCWData]⚠️ fill list: JSON is not an array")
                    } else
                        console.warn("[CCWData]⚠️ fill list: list is not selected")
                }
            }, {
                key: "getJSONArrayFromList",
                value: function(t, e) {
                    if ("empty" === t.LIST)
                        return console.warn("[CCWData]⚠️ get JSON from a list: list is not selected"),
                        "error: list is not selected";
                    var r = this.lookupListByIdOrName(t.LIST, e);
                    if (!r)
                        return console.warn("[CCWData]⚠️ get JSON from a list: list not found"),
                        "error: list not found";
                    var a = [];
                    "convert" === t.METHOD ? r.value.forEach((function(t) {
                        try {
                            a.push(JSON.parse(t))
                        } catch (e) {
                            a.push(t)
                        }
                    }
                    )) : a = r.value;
                    try {
                        return JSON.stringify(a)
                    } catch (t) {
                        return console.warn("[CCWData]⚠️ get JSON from a list: JSON Array cannot be converted to string ".concat(t.message)),
                        "error: JSON Array cannot be converted to string"
                    }
                }
            }, {
                key: "setProjectDataCachePolicy",
                value: function(t) {
                    var e = t.KEY
                      , r = t.CACHE;
                    this._setProjectDataCachePolicy(this._getCacheKey(e), r)
                }
            }, {
                key: "setProjectDataCachePolicyByBatch",
                value: function(t) {
                    var e = this
                      , r = t.KEYS_STR
                      , a = t.CACHE;
                    r.split(",").forEach((function(t) {
                        e._setProjectDataCachePolicy(e._getCacheKey(t), a)
                    }
                    ))
                }
            }, {
                key: "findAllList",
                value: function() {
                    var t = []
                      , e = this.runtime._stageTarget.variables;
                    Object.keys(e).forEach((function(r) {
                        "list" === e[r].type && t.push({
                            text: "".concat(e[r].name),
                            value: e[r].id
                        })
                    }
                    ));
                    try {
                        e = this.runtime._editingTarget.variables
                    } catch (t) {
                        e = "e"
                    }
                    return "e" !== e && this.runtime._editingTarget !== this.runtime._stageTarget && Object.keys(e).forEach((function(r) {
                        "list" === e[r].type && t.push({
                            text: "[PRIVATE]".concat(e[r].name),
                            value: e[r].id
                        })
                    }
                    )),
                    0 === t.length && t.push({
                        text: "-",
                        value: "empty"
                    }),
                    t
                }
            }],
            r && T(e.prototype, r),
            Object.defineProperty(e, "prototype", {
                writable: !1
            }),
            t
        }()
    }
    ,
    49576: (t, e, r) => {
        function a(t, e, r) {
            return a = n() ? Reflect.construct.bind() : function(t, e, r) {
                var a = [null];
                a.push.apply(a, e);
                var n = new (Function.bind.apply(t, a));
                return r && o(n, r.prototype),
                n
            }
            ,
            a.apply(null, arguments)
        }
        function n() {
            if ("undefined" == typeof Reflect || !Reflect.construct)
                return !1;
            if (Reflect.construct.sham)
                return !1;
            if ("function" == typeof Proxy)
                return !0;
            try {
                return Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], (function() {}
                ))),
                !0
            } catch (t) {
                return !1
            }
        }
        function o(t, e) {
            return o = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function(t, e) {
                return t.__proto__ = e,
                t
            }
            ,
            o(t, e)
        }
        function c(t) {
            return function(t) {
                if (Array.isArray(t))
                    return s(t)
            }(t) || function(t) {
                if ("undefined" != typeof Symbol && null != t[Symbol.iterator] || null != t["@@iterator"])
                    return Array.from(t)
            }(t) || i(t) || function() {
                throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
            }()
        }
        function i(t, e) {
            if (t) {
                if ("string" == typeof t)
                    return s(t, e);
                var r = Object.prototype.toString.call(t).slice(8, -1);
                return "Object" === r && t.constructor && (r = t.constructor.name),
                "Map" === r || "Set" === r ? Array.from(t) : "Arguments" === r || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r) ? s(t, e) : void 0
            }
        }
        function s(t, e) {
            (null == e || e > t.length) && (e = t.length);
            for (var r = 0, a = new Array(e); r < e; r++)
                a[r] = t[r];
            return a
        }
        r.d(e, {
            Br: () => p,
            O3: () => C,
            ZK: () => f,
            g4: () => h,
            nC: () => l,
            sq: () => d,
            vU: () => y
        });
        var u = function(t) {
            return t.map((function(t) {
                var e = t;
                if (t instanceof Object)
                    try {
                        e = JSON.stringify(t)
                    } catch (t) {
                        e = "TypeError: The message is abnormal and cannot be output."
                    }
                return e
            }
            ))
        }
          , l = function(t, e) {
            var r = {};
            return Object.entries(t).forEach((function(t) {
                var a, n, o = (n = 2,
                function(t) {
                    if (Array.isArray(t))
                        return t
                }(a = t) || function(t, e) {
                    var r = null == t ? null : "undefined" != typeof Symbol && t[Symbol.iterator] || t["@@iterator"];
                    if (null != r) {
                        var a, n, o = [], c = !0, i = !1;
                        try {
                            for (r = r.call(t); !(c = (a = r.next()).done) && (o.push(a.value),
                            !e || o.length !== e); c = !0)
                                ;
                        } catch (t) {
                            i = !0,
                            n = t
                        } finally {
                            try {
                                c || null == r.return || r.return()
                            } finally {
                                if (i)
                                    throw n
                            }
                        }
                        return o
                    }
                }(a, n) || i(a, n) || function() {
                    throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
                }()), c = o[0], s = o[1];
                r["".concat(e, ".").concat(c)] = s
            }
            )),
            r
        }
          , h = function() {
            for (var t, e = arguments.length, r = new Array(e), a = 0; a < e; a++)
                r[a] = arguments[a];
            var n, o = ["[INFO] : "].concat(c(u(r))).join(" ");
            null === (t = document.GandiBridge) || void 0 === t || t.dispatchEvent(new CustomEvent("trace",{
                detail: {
                    message: o
                }
            })),
            (document.enableTrace || window.debugVM) && (n = console).info.apply(n, r)
        }
          , f = function() {
            for (var t, e = arguments.length, r = new Array(e), a = 0; a < e; a++)
                r[a] = arguments[a];
            var n, o = ["[WARNING] : "].concat(c(u(r))).join(" ");
            null === (t = document.GandiBridge) || void 0 === t || t.dispatchEvent(new CustomEvent("warn",{
                detail: {
                    message: o
                }
            })),
            document.enableTrace && (n = console).warn.apply(n, r)
        }
          , y = function() {
            for (var t, e = arguments.length, r = new Array(e), a = 0; a < e; a++)
                r[a] = arguments[a];
            var n, o = ["[ERROR] : "].concat(c(u(r))).join(" ");
            null === (t = document.GandiBridge) || void 0 === t || t.dispatchEvent(new CustomEvent("error",{
                detail: {
                    message: o
                }
            })),
            document.enableTrace && (n = console).error.apply(n, r)
        }
          , d = function() {
            for (var t = "!#$%()*+,-./:;=?@[]^_`{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", e = t.length, r = [], a = 0; a < 20; a++)
                r[a] = t.charAt(Math.random() * e);
            return r.join("")
        }
          , C = {
            ALL_TAG: "#GANDI_CONST_ALL_TAG#",
            STAGE_TAG: "_stage_",
            MYSELF_TAG: "_myself_"
        };
        function p(t) {
            var e = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {}
              , r = ["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "Worker", "alert", "confirm", "prompt", "setTimeout", "setInterval", "Function", "Image", "Audio", "Video", "open"]
              , n = {}
              , o = window.Function;
            r.forEach((function(t) {
                n[t] = window[t],
                window[t] = null
            }
            ));
            try {
                var c = Object.keys(e)
                  , i = Object.values(e)
                  , s = '\n      "use strict";\n      const globalThis = null;\n      const window = null;\n      const document = null;\n      const alert = null;\n      const confirm = null;\n      const prompt = null;\n      const fetch = null;\n      const XMLHttpRequest = null;\n      const localStorage = null;\n      const sessionStorage = null;\n      const Image = null;\n      const Audio = null;\n      const Video = null;\n      const Worker = null;\n      const Function = null;\n      const open = null;\n      const history = null;\n      const location = null;\n      const navigator = null;\n      const global = null;\n      const self = null;\n      const top = null;\n      const parent = null;\n      const console = null;\n      '.concat(t)
                  , u = a(o, c.concat([s]));
                return u.apply(void 0, i)
            } finally {
                r.forEach((function(t) {
                    window[t] = n[t]
                }
                ))
            }
        }
    }
}]);
