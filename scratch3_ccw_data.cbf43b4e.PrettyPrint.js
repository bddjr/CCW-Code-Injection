/*! For license information please see scratch3_ccw_data.cbf43b4e.js.LICENSE.txt */
"use strict";
(self.webpackChunkscratch_extensions = self.webpackChunkscratch_extensions || []).push([[194], {
    12960: (e, t, r) => {
        r.d(t, {
            Z: () => y,
            w: () => u
        });
        var a = r(36808)
          , n = r.n(a)
          , _ = r(17563)
          , o = r(97865)
          , c = ["page", "perPage", "sortField", "sortType"];
        function i(e, t) {
            var r = Object.keys(e);
            if (Object.getOwnPropertySymbols) {
                var a = Object.getOwnPropertySymbols(e);
                t && (a = a.filter((function(t) {
                    return Object.getOwnPropertyDescriptor(e, t).enumerable
                }
                ))),
                r.push.apply(r, a)
            }
            return r
        }
        function s(e, t, r) {
            return t in e ? Object.defineProperty(e, t, {
                value: r,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = r,
            e
        }
        var u = {
            USER: "user",
            PROJECT: "project"
        }
          , l = {
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
          , p = function(e, t) {
            var r = t.page
              , a = t.perPage
              , n = t.sortField
              , o = t.sortType
              , u = void 0 === o ? "DESC" : o
              , l = function(e, t) {
                if (null == e)
                    return {};
                var r, a, n = function(e, t) {
                    if (null == e)
                        return {};
                    var r, a, n = {}, _ = Object.keys(e);
                    for (a = 0; a < _.length; a++)
                        r = _[a],
                        t.indexOf(r) >= 0 || (n[r] = e[r]);
                    return n
                }(e, t);
                if (Object.getOwnPropertySymbols) {
                    var _ = Object.getOwnPropertySymbols(e);
                    for (a = 0; a < _.length; a++)
                        r = _[a],
                        t.indexOf(r) >= 0 || Object.prototype.propertyIsEnumerable.call(e, r) && (n[r] = e[r])
                }
                return n
            }(t, c);
            return "".concat(e, "?").concat(_.stringify(function(e) {
                for (var t = 1; t < arguments.length; t++) {
                    var r = null != arguments[t] ? arguments[t] : {};
                    t % 2 ? i(Object(r), !0).forEach((function(t) {
                        s(e, t, r[t])
                    }
                    )) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(r)) : i(Object(r)).forEach((function(t) {
                        Object.defineProperty(e, t, Object.getOwnPropertyDescriptor(r, t))
                    }
                    ))
                }
                return e
            }({
                page: r,
                perPage: a,
                sortField: n,
                sortType: u || "DESC"
            }, l)))
        };
        const y = function() {
            var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : ""
              , t = e
              , r = t.includes("cocrea.world")
              , a = r ? l.COCREA : l.CCW
              , _ = {}
              , c = Boolean(n().get("debugLog"))
              , i = function(e) {
                var n = e.accessKey
                  , i = e.primaryKey
                  , s = e.secondaryKey
                  , l = e.filterKeys
                  , p = void 0 === l ? [] : l
                  , y = e.DBType !== u.USER || r ? i : "".concat(i, "-u")
                  , C = n + y + s + p.toString();
                if (!_[C]) {
                    var f;
                    if (t.includes("cocrea.world")) {
                        var h = p.join(",");
                        f = (0,
                        o.U2)(t + a.get, {
                            params: {
                                accessKey: n,
                                primaryKey: y,
                                secondaryKey: s,
                                filterKeys: h
                            }
                        }).finally((function() {
                            delete _[C]
                        }
                        ))
                    } else
                        f = (0,
                        o.v_)(t + a.get, {
                            accessKey: n,
                            primaryKey: y,
                            secondaryKey: s,
                            filterKeys: p
                        }).finally((function() {
                            delete _[C]
                        }
                        ));
                    return _[C] = f,
                    c && console.log("[cloud DB] new get value request with id: ", _),
                    f
                }
                return c && console.log("[cloud DB]same request is in wait with id:  ", C),
                _[C]
            }
              , s = function(e) {
                var n = e.primaryKey
                  , _ = e.secondaryKey
                  , c = e.value
                  , i = {
                    primaryKey: e.DBType !== u.USER || r ? n : "".concat(n, "-u"),
                    secondaryKey: _,
                    value: c
                };
                return (0,
                o.v_)("".concat(t + a.set), i)
            }
              , y = function(e) {
                var n = e.accessKey
                  , _ = e.primaryKey
                  , c = e.secondaryKeys
                  , i = e.filterKeys
                  , s = void 0 === i ? [] : i
                  , l = e.DBType !== u.USER || r ? _ : "".concat(_, "-u");
                return (0,
                o.v_)(t + a.getList, {
                    accessKey: n,
                    primaryKey: l,
                    secondaryKeys: c,
                    filterKeys: s
                })
            }
              , C = function() {
                var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "";
                r = (t = null != e ? e : "").includes("cocrea.world"),
                a = r ? l.COCREA : l.CCW
            }
              , f = function(e) {
                var r = p("".concat(t, "/creation_data_access_config/permission/page"), {
                    page: 1,
                    perPage: 50
                });
                return (0,
                o.v_)(r, {
                    grantedCreationOid: e
                })
            };
            return {
                get: i,
                set: s,
                getList: y,
                setHost: C,
                getConnectedList: f
            }
        }
    }
    ,
    97865: (e, t, r) => {
        r.d(t, {
            U2: () => n,
            v_: () => _
        });
        var a = (0,
        r(7055).create)({
            timeout: 3e4,
            checkApiHostBasedPageRouting: !0,
            environment: "prod",
            apiVersion: "1.1",
            withCredentials: !0
        });
        a.use((function(e, t) {
            t.use((function(e) {
                if (200 != +e.data.status) {
                    var t = e.config
                      , r = t.skipErrorHandler
                      , a = t.skipErrorCodes;
                    r || (void 0 === a ? [] : a).includes(e.data.code) || function(e) {
                        var t = e.data
                          , r = t.code
                          , a = t.msg;
                        throw new Error("Request Error： code: ".concat(r, ", msg: ").concat(a))
                    }(e)
                }
                return e.config.skipTransformResponse ? e.data : e.data.body
            }
            ))
        }
        ));
        var n = a.get
          , _ = (a.put,
        a.post);
        a.patch,
        a.delete
    }
    ,
    12095: (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__),
        __webpack_require__.d(__webpack_exports__, {
            default: () => CCWData
        });
        var lodash_es_debounce__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(98956)
          , scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(80673)
          , scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default = __webpack_require__.n(scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0__)
          , scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(29122)
          , scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default = __webpack_require__.n(scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1__)
          , scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(83392)
          , scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default = __webpack_require__.n(scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2__)
          , lodash_es__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(27771)
          , _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(12960)
          , _assets_icon_svg__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(19288)
          , _util_gandi_util__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(49576)
          , _tokenizr__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(85051);
        function _typeof(e) {
            return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                return typeof e
            }
            : function(e) {
                return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
            }
            ,
            _typeof(e)
        }
        function ownKeys(e, t) {
            var r = Object.keys(e);
            if (Object.getOwnPropertySymbols) {
                var a = Object.getOwnPropertySymbols(e);
                t && (a = a.filter((function(t) {
                    return Object.getOwnPropertyDescriptor(e, t).enumerable
                }
                ))),
                r.push.apply(r, a)
            }
            return r
        }
        function _objectSpread(e) {
            for (var t = 1; t < arguments.length; t++) {
                var r = null != arguments[t] ? arguments[t] : {};
                t % 2 ? ownKeys(Object(r), !0).forEach((function(t) {
                    _defineProperty(e, t, r[t])
                }
                )) : Object.getOwnPropertyDescriptors ? Object.defineProperties(e, Object.getOwnPropertyDescriptors(r)) : ownKeys(Object(r)).forEach((function(t) {
                    Object.defineProperty(e, t, Object.getOwnPropertyDescriptor(r, t))
                }
                ))
            }
            return e
        }
        function _regeneratorRuntime() {
            _regeneratorRuntime = function() {
                return e
            }
            ;
            var e = {}
              , t = Object.prototype
              , r = t.hasOwnProperty
              , a = Object.defineProperty || function(e, t, r) {
                e[t] = r.value
            }
              , n = "function" == typeof Symbol ? Symbol : {}
              , _ = n.iterator || "@@iterator"
              , o = n.asyncIterator || "@@asyncIterator"
              , c = n.toStringTag || "@@toStringTag";
            function i(e, t, r) {
                return Object.defineProperty(e, t, {
                    value: r,
                    enumerable: !0,
                    configurable: !0,
                    writable: !0
                }),
                e[t]
            }
            try {
                i({}, "")
            } catch (e) {
                i = function(e, t, r) {
                    return e[t] = r
                }
            }
            function s(e, t, r, n) {
                var _ = t && t.prototype instanceof p ? t : p
                  , o = Object.create(_.prototype)
                  , c = new T(n || []);
                return a(o, "_invoke", {
                    value: m(e, r, c)
                }),
                o
            }
            function u(e, t, r) {
                try {
                    return {
                        type: "normal",
                        arg: e.call(t, r)
                    }
                } catch (e) {
                    return {
                        type: "throw",
                        arg: e
                    }
                }
            }
            e.wrap = s;
            var l = {};
            function p() {}
            function y() {}
            function C() {}
            var f = {};
            i(f, _, (function() {
                return this
            }
            ));
            var h = Object.getPrototypeOf
              , d = h && h(h(I([])));
            d && d !== t && r.call(d, _) && (f = d);
            var D = C.prototype = p.prototype = Object.create(f);
            function E(e) {
                ["next", "throw", "return"].forEach((function(t) {
                    i(e, t, (function(e) {
                        return this._invoke(t, e)
                    }
                    ))
                }
                ))
            }
            function O(e, t) {
                function n(a, _, o, c) {
                    var i = u(e[a], e, _);
                    if ("throw" !== i.type) {
                        var s = i.arg
                          , l = s.value;
                        return l && "object" == _typeof(l) && r.call(l, "__await") ? t.resolve(l.__await).then((function(e) {
                            n("next", e, o, c)
                        }
                        ), (function(e) {
                            n("throw", e, o, c)
                        }
                        )) : t.resolve(l).then((function(e) {
                            s.value = e,
                            o(s)
                        }
                        ), (function(e) {
                            return n("throw", e, o, c)
                        }
                        ))
                    }
                    c(i.arg)
                }
                var _;
                a(this, "_invoke", {
                    value: function(e, r) {
                        function a() {
                            return new t((function(t, a) {
                                n(e, r, t, a)
                            }
                            ))
                        }
                        return _ = _ ? _.then(a, a) : a()
                    }
                })
            }
            function m(e, t, r) {
                var a = "suspendedStart";
                return function(n, _) {
                    if ("executing" === a)
                        throw new Error("Generator is already running");
                    if ("completed" === a) {
                        if ("throw" === n)
                            throw _;
                        return {
                            value: void 0,
                            done: !0
                        }
                    }
                    for (r.method = n,
                    r.arg = _; ; ) {
                        var o = r.delegate;
                        if (o) {
                            var c = g(o, r);
                            if (c) {
                                if (c === l)
                                    continue;
                                return c
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
                        var i = u(e, t, r);
                        if ("normal" === i.type) {
                            if (a = r.done ? "completed" : "suspendedYield",
                            i.arg === l)
                                continue;
                            return {
                                value: i.arg,
                                done: r.done
                            }
                        }
                        "throw" === i.type && (a = "completed",
                        r.method = "throw",
                        r.arg = i.arg)
                    }
                }
            }
            function g(e, t) {
                var r = e.iterator[t.method];
                if (void 0 === r) {
                    if (t.delegate = null,
                    "throw" === t.method) {
                        if (e.iterator.return && (t.method = "return",
                        t.arg = void 0,
                        g(e, t),
                        "throw" === t.method))
                            return l;
                        t.method = "throw",
                        t.arg = new TypeError("The iterator does not provide a 'throw' method")
                    }
                    return l
                }
                var a = u(r, e.iterator, t.arg);
                if ("throw" === a.type)
                    return t.method = "throw",
                    t.arg = a.arg,
                    t.delegate = null,
                    l;
                var n = a.arg;
                return n ? n.done ? (t[e.resultName] = n.value,
                t.next = e.nextLoc,
                "return" !== t.method && (t.method = "next",
                t.arg = void 0),
                t.delegate = null,
                l) : n : (t.method = "throw",
                t.arg = new TypeError("iterator result is not an object"),
                t.delegate = null,
                l)
            }
            function v(e) {
                var t = {
                    tryLoc: e[0]
                };
                1 in e && (t.catchLoc = e[1]),
                2 in e && (t.finallyLoc = e[2],
                t.afterLoc = e[3]),
                this.tryEntries.push(t)
            }
            function P(e) {
                var t = e.completion || {};
                t.type = "normal",
                delete t.arg,
                e.completion = t
            }
            function T(e) {
                this.tryEntries = [{
                    tryLoc: "root"
                }],
                e.forEach(v, this),
                this.reset(!0)
            }
            function I(e) {
                if (e) {
                    var t = e[_];
                    if (t)
                        return t.call(e);
                    if ("function" == typeof e.next)
                        return e;
                    if (!isNaN(e.length)) {
                        var a = -1
                          , n = function t() {
                            for (; ++a < e.length; )
                                if (r.call(e, a))
                                    return t.value = e[a],
                                    t.done = !1,
                                    t;
                            return t.value = void 0,
                            t.done = !0,
                            t
                        };
                        return n.next = n
                    }
                }
                return {
                    next: B
                }
            }
            function B() {
                return {
                    value: void 0,
                    done: !0
                }
            }
            return y.prototype = C,
            a(D, "constructor", {
                value: C,
                configurable: !0
            }),
            a(C, "constructor", {
                value: y,
                configurable: !0
            }),
            y.displayName = i(C, c, "GeneratorFunction"),
            e.isGeneratorFunction = function(e) {
                var t = "function" == typeof e && e.constructor;
                return !!t && (t === y || "GeneratorFunction" === (t.displayName || t.name))
            }
            ,
            e.mark = function(e) {
                return Object.setPrototypeOf ? Object.setPrototypeOf(e, C) : (e.__proto__ = C,
                i(e, c, "GeneratorFunction")),
                e.prototype = Object.create(D),
                e
            }
            ,
            e.awrap = function(e) {
                return {
                    __await: e
                }
            }
            ,
            E(O.prototype),
            i(O.prototype, o, (function() {
                return this
            }
            )),
            e.AsyncIterator = O,
            e.async = function(t, r, a, n, _) {
                void 0 === _ && (_ = Promise);
                var o = new O(s(t, r, a, n),_);
                return e.isGeneratorFunction(r) ? o : o.next().then((function(e) {
                    return e.done ? e.value : o.next()
                }
                ))
            }
            ,
            E(D),
            i(D, c, "Generator"),
            i(D, _, (function() {
                return this
            }
            )),
            i(D, "toString", (function() {
                return "[object Generator]"
            }
            )),
            e.keys = function(e) {
                var t = Object(e)
                  , r = [];
                for (var a in t)
                    r.push(a);
                return r.reverse(),
                function e() {
                    for (; r.length; ) {
                        var a = r.pop();
                        if (a in t)
                            return e.value = a,
                            e.done = !1,
                            e
                    }
                    return e.done = !0,
                    e
                }
            }
            ,
            e.values = I,
            T.prototype = {
                constructor: T,
                reset: function(e) {
                    if (this.prev = 0,
                    this.next = 0,
                    this.sent = this._sent = void 0,
                    this.done = !1,
                    this.delegate = null,
                    this.method = "next",
                    this.arg = void 0,
                    this.tryEntries.forEach(P),
                    !e)
                        for (var t in this)
                            "t" === t.charAt(0) && r.call(this, t) && !isNaN(+t.slice(1)) && (this[t] = void 0)
                },
                stop: function() {
                    this.done = !0;
                    var e = this.tryEntries[0].completion;
                    if ("throw" === e.type)
                        throw e.arg;
                    return this.rval
                },
                dispatchException: function(e) {
                    if (this.done)
                        throw e;
                    var t = this;
                    function a(r, a) {
                        return o.type = "throw",
                        o.arg = e,
                        t.next = r,
                        a && (t.method = "next",
                        t.arg = void 0),
                        !!a
                    }
                    for (var n = this.tryEntries.length - 1; n >= 0; --n) {
                        var _ = this.tryEntries[n]
                          , o = _.completion;
                        if ("root" === _.tryLoc)
                            return a("end");
                        if (_.tryLoc <= this.prev) {
                            var c = r.call(_, "catchLoc")
                              , i = r.call(_, "finallyLoc");
                            if (c && i) {
                                if (this.prev < _.catchLoc)
                                    return a(_.catchLoc, !0);
                                if (this.prev < _.finallyLoc)
                                    return a(_.finallyLoc)
                            } else if (c) {
                                if (this.prev < _.catchLoc)
                                    return a(_.catchLoc, !0)
                            } else {
                                if (!i)
                                    throw new Error("try statement without catch or finally");
                                if (this.prev < _.finallyLoc)
                                    return a(_.finallyLoc)
                            }
                        }
                    }
                },
                abrupt: function(e, t) {
                    for (var a = this.tryEntries.length - 1; a >= 0; --a) {
                        var n = this.tryEntries[a];
                        if (n.tryLoc <= this.prev && r.call(n, "finallyLoc") && this.prev < n.finallyLoc) {
                            var _ = n;
                            break
                        }
                    }
                    _ && ("break" === e || "continue" === e) && _.tryLoc <= t && t <= _.finallyLoc && (_ = null);
                    var o = _ ? _.completion : {};
                    return o.type = e,
                    o.arg = t,
                    _ ? (this.method = "next",
                    this.next = _.finallyLoc,
                    l) : this.complete(o)
                },
                complete: function(e, t) {
                    if ("throw" === e.type)
                        throw e.arg;
                    return "break" === e.type || "continue" === e.type ? this.next = e.arg : "return" === e.type ? (this.rval = this.arg = e.arg,
                    this.method = "return",
                    this.next = "end") : "normal" === e.type && t && (this.next = t),
                    l
                },
                finish: function(e) {
                    for (var t = this.tryEntries.length - 1; t >= 0; --t) {
                        var r = this.tryEntries[t];
                        if (r.finallyLoc === e)
                            return this.complete(r.completion, r.afterLoc),
                            P(r),
                            l
                    }
                },
                catch: function(e) {
                    for (var t = this.tryEntries.length - 1; t >= 0; --t) {
                        var r = this.tryEntries[t];
                        if (r.tryLoc === e) {
                            var a = r.completion;
                            if ("throw" === a.type) {
                                var n = a.arg;
                                P(r)
                            }
                            return n
                        }
                    }
                    throw new Error("illegal catch attempt")
                },
                delegateYield: function(e, t, r) {
                    return this.delegate = {
                        iterator: I(e),
                        resultName: t,
                        nextLoc: r
                    },
                    "next" === this.method && (this.arg = void 0),
                    l
                }
            },
            e
        }
        function asyncGeneratorStep(e, t, r, a, n, _, o) {
            try {
                var c = e[_](o)
                  , i = c.value
            } catch (e) {
                return void r(e)
            }
            c.done ? t(i) : Promise.resolve(i).then(a, n)
        }
        function _asyncToGenerator(e) {
            return function() {
                var t = this
                  , r = arguments;
                return new Promise((function(a, n) {
                    var _ = e.apply(t, r);
                    function o(e) {
                        asyncGeneratorStep(_, a, n, o, c, "next", e)
                    }
                    function c(e) {
                        asyncGeneratorStep(_, a, n, o, c, "throw", e)
                    }
                    o(void 0)
                }
                ))
            }
        }
        function _classCallCheck(e, t) {
            if (!(e instanceof t))
                throw new TypeError("Cannot call a class as a function")
        }
        function _defineProperties(e, t) {
            for (var r = 0; r < t.length; r++) {
                var a = t[r];
                a.enumerable = a.enumerable || !1,
                a.configurable = !0,
                "value"in a && (a.writable = !0),
                Object.defineProperty(e, a.key, a)
            }
        }
        function _createClass(e, t, r) {
            return t && _defineProperties(e.prototype, t),
            r && _defineProperties(e, r),
            Object.defineProperty(e, "prototype", {
                writable: !1
            }),
            e
        }
        function _defineProperty(e, t, r) {
            return t in e ? Object.defineProperty(e, t, {
                value: r,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : e[t] = r,
            e
        }
        var CACHE_POLICY = {
            NO_CACHE: "CCWData.CACHE_POLICY.NO_CACHE",
            CACHE_2S: "CCWData.CACHE_POLICY.CACHE_2S",
            INFINITY: "CCWData.CACHE_POLICY.INFINITY"
        }
          , CCWData = function() {
            function CCWData(e) {
                var t = this;
                if (_classCallCheck(this, CCWData),
                _defineProperty(this, "clearAll", (function() {
                    t._projectCache = {},
                    t._projectCachedTimeout = {},
                    t._projectDataCachePolicy = {},
                    t._userCache = {}
                }
                )),
                _defineProperty(this, "refreshConnectedList", function() {
                    var e = _asyncToGenerator(_regeneratorRuntime().mark((function e(r) {
                        var a, n, _, o, c;
                        return _regeneratorRuntime().wrap((function(e) {
                            for (; ; )
                                switch (e.prev = e.next) {
                                case 0:
                                    return e.prev = 0,
                                    t.$reloadBtnTextTag = r.svgGroup_.querySelector(".blocklyText"),
                                    _ = 3,
                                    o = t._formatMessage("CCWData.loading"),
                                    t.intervalId = setInterval((function() {
                                        t.$reloadBtnTextTag.textContent = "".concat(o).concat(".".repeat(++_ % 4))
                                    }
                                    ), 300),
                                    e.next = 7,
                                    null === (a = t.cloudDB) || void 0 === a ? void 0 : a.getConnectedList(t.projectId);
                                case 7:
                                    c = e.sent,
                                    t.connectedDataBaseList = null === (n = c.data) || void 0 === n ? void 0 : n.filter((function(e) {
                                        var r;
                                        return e.creationOid !== t.projectId && e.creationOid && (null === (r = e.creation) || void 0 === r ? void 0 : r.title)
                                    }
                                    )).map((function(e) {
                                        var t;
                                        return {
                                            text: null === (t = e.creation) || void 0 === t ? void 0 : t.title,
                                            value: e.creationOid
                                        }
                                    }
                                    )),
                                    setTimeout((function() {
                                        clearInterval(t.intervalId),
                                        t.$reloadBtnTextTag.textContent = t._formatMessage("CCWData.loadingFinish"),
                                        setTimeout((function() {
                                            t.$reloadBtnTextTag.textContent = t._formatMessage("CCWData.syncDataBase")
                                        }
                                        ), 2e3)
                                    }
                                    ), 1e3),
                                    e.next = 18;
                                    break;
                                case 12:
                                    e.prev = 12,
                                    e.t0 = e.catch(0),
                                    console.warn("syncDataBase list error", e.t0),
                                    clearInterval(t.intervalId),
                                    t.$reloadBtnTextTag.textContent = t._formatMessage("CCWData.loadingFail"),
                                    t.connectedDataBaseList = null;
                                case 18:
                                case "end":
                                    return e.stop()
                                }
                        }
                        ), e, null, [[0, 12]])
                    }
                    )));
                    return function(t) {
                        return e.apply(this, arguments)
                    }
                }()),
                _defineProperty(this, "initUUID", _asyncToGenerator(_regeneratorRuntime().mark((function e() {
                    var r, a;
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                if (!t.runtime.ccwAPI) {
                                    e.next = 7;
                                    break
                                }
                                if (t.runtime.ccwAPI.getProjectUUID && (r = t.runtime.ccwAPI.getProjectUUID(),
                                t.ccwProjectUUID !== r && (t.ccwProjectUUID = r,
                                t._projectCache = {},
                                t._projectCachedTimeout = {},
                                t._projectDataCachePolicy = {}),
                                t.ccwProjectUUID || console.error("CCW API: getProjectUUID return null", t.ccwProjectUUID)),
                                !t.runtime.ccwAPI.getUserInfo) {
                                    e.next = 7;
                                    break
                                }
                                return e.next = 5,
                                t.runtime.ccwAPI.getUserInfo();
                            case 5:
                                (a = e.sent) && t.ccwUserUUID !== a.userId && (t.ccwUserUUID = a.userId,
                                t._userCache = {},
                                t._userValueToBatchPush = {});
                            case 7:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e)
                }
                )))),
                _defineProperty(this, "sendPlayEventCodeBlock", (function() {
                    return {
                        hideFromPalette: !0,
                        opcode: "sendPlayEventCode",
                        text: t._formatMessage({
                            id: "CCWData.sendPlayEventCode"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            CODE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "code"
                            },
                            DATA: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "data"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "setValueBlock", (function() {
                    return {
                        opcode: "setValue",
                        text: t._formatMessage({
                            id: "CCWData.setValue"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: 0
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueBlock", (function() {
                    return {
                        opcode: "getValue",
                        text: t._formatMessage({
                            id: "CCWData.getValue"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "setValueToDBBlock", (function() {
                    return {
                        opcode: "setValueToDB",
                        text: t._formatMessage({
                            id: "CCWData.setValueToDB"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: 0
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueFromDBBlock", (function() {
                    return {
                        opcode: "getValueFromDB",
                        text: t._formatMessage({
                            id: "CCWData.getValueFromDB"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueListFromDBBlock", (function() {
                    return {
                        opcode: "getValueListFromDB",
                        text: t._formatMessage({
                            id: "CCWData.getValueListFromDB"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY_LIST: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "LIST_MENU"
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueListFromDBToListBlock", (function() {
                    return {
                        opcode: "getValueListFromDBToList",
                        text: t._formatMessage({
                            id: "CCWData.getValueListFromDBToList"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        disableMonitor: !0,
                        arguments: {
                            KEY_LIST: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "STATIC_LIST_MENU"
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            },
                            TO_LIST: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "STATIC_LIST_MENU"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueFromOtherProjectDBBlock", (function() {
                    return {
                        opcode: "getValueFromOtherProjectDB",
                        text: t._formatMessage({
                            id: "CCWData.getValueFromOtherProjectDB"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        hideFromPalette: !0,
                        arguments: {
                            PROJECT_ID: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "project_id"
                            },
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "getValueFromOtherProjectDBBlockV2", (function() {
                    return {
                        opcode: "getValueFromOtherProjectDB_V2",
                        text: t._formatMessage({
                            id: "CCWData.getValueFromOtherProjectDB"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            PROJECT_ID: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "CONNECTED_LIST"
                            },
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            DB: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "DB_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_isValid", (function() {
                    return {
                        opcode: "isValid",
                        text: t._formatMessage({
                            id: "CCWData.isValid"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        arguments: {
                            VALUE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "[1,2]"
                            },
                            TYPE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "any",
                                menu: "TYPE_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_getValueInJSON", (function() {
                    return {
                        opcode: "getValueInJSON",
                        text: t._formatMessage({
                            id: "CCWData.getValueInJSON"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        hideFromPalette: !0,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            JSON: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_getValueInJSON_2", (function() {
                    return {
                        opcode: "getValueInJSON_2",
                        text: t._formatMessage({
                            id: "CCWData.getValueInJSON_2"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            JSON: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_setValueInJSON", (function() {
                    return {
                        opcode: "setValueInJSON",
                        text: t._formatMessage({
                            id: "CCWData.setValueInJSON"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        hideFromPalette: !0,
                        disableMonitor: !0,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "new value"
                            },
                            JSON: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_setValueInJSON_2", (function() {
                    return {
                        opcode: "setValueInJSON_2",
                        text: t._formatMessage({
                            id: "CCWData.setValueInJSON_2"
                        }),
                        disableMonitor: !0,
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            VALUE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "new value"
                            },
                            JSON: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: '{"key":"value"}'
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_fillJSONArrayToList", (function() {
                    return {
                        opcode: "fillJSONArrayToList",
                        text: t._formatMessage({
                            id: "CCWData.fillJSONArrayToList"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            JSON: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "[1,2,3]"
                            },
                            LIST: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "LIST_MENU"
                            },
                            METHOD: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "replace",
                                menu: "METHOD_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_getJSONArrayFromList", (function() {
                    return {
                        opcode: "getJSONArrayFromList",
                        text: t._formatMessage({
                            id: "CCWData.getJSONArrayFromList"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().REPORTER,
                        disableMonitor: !0,
                        arguments: {
                            LIST: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                menu: "LIST_MENU"
                            },
                            METHOD: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "convert",
                                menu: "PARSE_METHOD_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_setProjectDataCachePolicy", (function() {
                    return {
                        opcode: "setProjectDataCachePolicy",
                        text: t._formatMessage({
                            id: "CCWData.setProjectDataCachePolicy"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            KEY: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key"
                            },
                            CACHE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: CACHE_POLICY.CACHE_2S,
                                menu: "CACHE_POLICY_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_setProjectDataCachePolicyByBatch", (function() {
                    return {
                        opcode: "setProjectDataCachePolicyByBatch",
                        text: t._formatMessage({
                            id: "CCWData.setProjectDataCachePolicyByBatch"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().COMMAND,
                        arguments: {
                            KEYS_STR: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: "key1,key2,key3"
                            },
                            CACHE: {
                                type: scratch_vm_src_extension_support_argument_type__WEBPACK_IMPORTED_MODULE_0___default().STRING,
                                defaultValue: CACHE_POLICY.CACHE_2S,
                                menu: "CACHE_POLICY_LIST"
                            }
                        }
                    }
                }
                )),
                _defineProperty(this, "block_getAllProjectDataCachePolicy", (function() {
                    return {
                        text: t._formatMessage({
                            id: "CCWData.getAllProjectDataCachePolicy"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().BUTTON,
                        onClick: function() {
                            var e = Object.keys(t._projectDataCachePolicy);
                            t.runtime.logSystem.show(),
                            0 === e.length ? t.runtime.logSystem.info("[CCWData]No custom cache policy, all use default 2s cache policy") : (t.runtime.logSystem.info("[CCWData] --- CCWData Cache Policy ---"),
                            e.forEach((function(e) {
                                t.runtime.logSystem.info("[CCWData] ".concat(e.split("-")[1], " : ").concat(t._formatMessage(t._projectDataCachePolicy[e])))
                            }
                            )))
                        }
                    }
                }
                )),
                _defineProperty(this, "block_resetAllProjectDataCachePolicy", (function() {
                    return {
                        text: t._formatMessage({
                            id: "CCWData.resetAllProjectDataCachePolicy"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().BUTTON,
                        onClick: function() {
                            Object.keys(t._projectDataCachePolicy).forEach((function(e) {
                                t._clearProjectCache(e),
                                delete t._projectDataCachePolicy[e]
                            }
                            ))
                        }
                    }
                }
                )),
                _defineProperty(this, "block_getConnectedDataBase", (function() {
                    return {
                        text: t._formatMessage({
                            id: "CCWData.syncDataBase"
                        }),
                        blockType: scratch_vm_src_extension_support_block_type__WEBPACK_IMPORTED_MODULE_1___default().BUTTON,
                        onClick: t.refreshConnectedList
                    }
                }
                )),
                _defineProperty(this, "_getConnectedList", (function() {
                    return t.connectedDataBaseList && 0 !== t.connectedDataBaseList.length ? t.connectedDataBaseList : [{
                        text: t._formatMessage({
                            id: "CCWData.syncDataBaseTip"
                        }),
                        value: "-"
                    }]
                }
                )),
                _defineProperty(this, "_getAllVariablesList", (function() {
                    var e = []
                      , r = t.runtime._stageTarget.variables;
                    Object.keys(r).forEach((function(t) {
                        "" === r[t].type && e.push({
                            text: "".concat(r[t].name),
                            value: r[t].id
                        })
                    }
                    ));
                    var a = t.runtime._editingTarget.variables;
                    return Object.keys(a).forEach((function(t) {
                        "" === a[t].type && e.push({
                            text: "*私有变量*".concat(a[t].name),
                            value: a[t].id
                        })
                    }
                    )),
                    0 === e.length && e.push({
                        text: "*请先创建变量*",
                        value: "empty"
                    }),
                    e
                }
                )),
                _defineProperty(this, "_getAllDBList", (function() {
                    return [{
                        text: t._formatMessage({
                            id: "CCWData.user",
                            default: "user data"
                        }),
                        value: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER
                    }, {
                        text: t._formatMessage({
                            id: "CCWData.project",
                            default: "project data"
                        }),
                        value: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT
                    }]
                }
                )),
                _defineProperty(this, "_getCacheKey", (function(e) {
                    return "".concat(t.projectId, "-").concat(e)
                }
                )),
                _defineProperty(this, "_clearProjectCache", (function(e) {
                    delete t._projectCache[e],
                    delete t._projectCachedTimeout[e]
                }
                )),
                _defineProperty(this, "_setProjectDataCachePolicy", (function(e, r) {
                    t._clearProjectCache(e),
                    t._projectDataCachePolicy[e] = r
                }
                )),
                _defineProperty(this, "_refreshProjectCacheTimeout", (function(e) {
                    var r = t._projectCachedTimeout[e];
                    if (r && clearTimeout(r),
                    t._projectDataCachePolicy[e] !== CACHE_POLICY.INFINITY) {
                        var a = setTimeout((function() {
                            t._clearProjectCache(e)
                        }
                        ), 2e3);
                        t._projectCachedTimeout[e] = a
                    }
                }
                )),
                _defineProperty(this, "_batchSetValuesToUser", (0,
                lodash_es_debounce__WEBPACK_IMPORTED_MODULE_6__.Z)(_asyncToGenerator(_regeneratorRuntime().mark((function e() {
                    var r, a;
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                if (null === (r = t.runtime.ccwAPI) || void 0 === r || !r.preActionInterceptor) {
                                    e.next = 3;
                                    break
                                }
                                return e.next = 3,
                                t.runtime.ccwAPI.preActionInterceptor();
                            case 3:
                                null === (a = t.cloudDB) || void 0 === a || a.set({
                                    primaryKey: t.projectId,
                                    secondaryKey: t.UserId,
                                    value: t._userValueToBatchPush,
                                    DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER
                                }).then((function() {
                                    t._userValueToBatchPush = {}
                                }
                                ));
                            case 4:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e)
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
                    var r = e.ccwAPI.getOnlineExtensionsConfig().hosts;
                    r && r.cloudDBHost && (this.host = r.cloudDBHost)
                }
                this.host ? (this.cloudDB = (0,
                _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.Z)(this.host),
                this.runtime.on("PROJECT_STOP_ALL", (function() {
                    t.clearAll()
                }
                )),
                this.runtime.on("CCWAPI_CHANGED", (function() {
                    t.initUUID()
                }
                )),
                this.initUUID()) : console.warn("CCWData: host is not provided, stop init")
            }
            var _getValueListFromDB3, _getValueListFromDB2, _getValueFromOtherProjectDB_V, _setValueToProject2;
            return _createClass(CCWData, [{
                key: "getInfo",
                value: function() {
                    return {
                        id: "CCWData",
                        name: this._formatMessage({
                            id: "CCWData.name",
                            default: "CCWData"
                        }),
                        color1: "#ED35A3",
                        menuIconURI: _assets_icon_svg__WEBPACK_IMPORTED_MODULE_7__.Z,
                        blockIconURI: _assets_icon_svg__WEBPACK_IMPORTED_MODULE_7__.Z,
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
                                text: this._formatMessage(CACHE_POLICY.INFINITY),
                                value: CACHE_POLICY.INFINITY
                            }, {
                                text: this._formatMessage(CACHE_POLICY.CACHE_2S),
                                value: CACHE_POLICY.CACHE_2S
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
                value: (_setValueToProject2 = _asyncToGenerator(_regeneratorRuntime().mark((function e(t, r) {
                    var a, n, _;
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                if (a = this._getCacheKey(t),
                                this._projectCache[a] === r) {
                                    e.next = 8;
                                    break
                                }
                                if (this._projectCache[a] = r,
                                this._refreshProjectCacheTimeout(a),
                                null === (n = this.runtime.ccwAPI) || void 0 === n || !n.preActionInterceptor) {
                                    e.next = 7;
                                    break
                                }
                                return e.next = 7,
                                this.runtime.ccwAPI.preActionInterceptor();
                            case 7:
                                return e.abrupt("return", null === (_ = this.cloudDB) || void 0 === _ ? void 0 : _.set({
                                    primaryKey: this.projectId,
                                    secondaryKey: t,
                                    value: {
                                        v: r
                                    },
                                    DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT
                                }));
                            case 8:
                                return e.abrupt("return", Promise.resolve("value not changed"));
                            case 9:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e, this)
                }
                ))),
                function(e, t) {
                    return _setValueToProject2.apply(this, arguments)
                }
                )
            }, {
                key: "_getValueFromProject",
                value: function(e) {
                    var t, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = "".concat(a, "-").concat(e);
                    return Object.prototype.hasOwnProperty.call(this._projectCache, n) ? this._projectCache[n] : null === (t = this.cloudDB) || void 0 === t ? void 0 : t.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: e,
                        DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT
                    }).then((function(e) {
                        return r._projectCache[n] = e.v || "",
                        r._refreshProjectCacheTimeout(n),
                        r._projectCache[n]
                    }
                    ))
                }
            }, {
                key: "_getListValueFromProject",
                value: function(e) {
                    var t, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = [], _ = [], o = "ccw_loading_";
                    return e.forEach((function(e) {
                        var t = "".concat(a, "-").concat(e);
                        r._projectCache[t] && r._projectCachedTimeout[t] ? n.push(r._projectCache[t]) : (n.push(o + e),
                        _.push(e))
                    }
                    )),
                    _.length > 0 ? null === (t = this.cloudDB) || void 0 === t ? void 0 : t.getList({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKeys: _,
                        DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT
                    }).then((function(e) {
                        return e ? n.map((function(t) {
                            if (t.startsWith(o)) {
                                var n = t.replace(o, "")
                                  , _ = "".concat(a, "-").concat(n)
                                  , c = e[n].v;
                                return r._projectCache[_] = c,
                                r._refreshProjectCacheTimeout(_),
                                c
                            }
                            return t
                        }
                        )) : null
                    }
                    )) : n
                }
            }, {
                key: "_setValueToUser",
                value: function(e, t) {
                    var r = this._getCacheKey(e);
                    this._userCache[r] !== t && (this._userCache[r] = t,
                    this._userValueToBatchPush[e] = t,
                    this._batchSetValuesToUser())
                }
            }, {
                key: "_getValueFromUser",
                value: function(e) {
                    var t, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = "".concat(a, "-").concat(e);
                    return Object.prototype.hasOwnProperty.call(this._userCache, n) ? this._userCache[n] : null === (t = this.cloudDB) || void 0 === t ? void 0 : t.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: this.UserId,
                        filterKeys: [e],
                        DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER
                    }).then((function(t) {
                        return r._userCache[n] = t[e] || "",
                        r._userCache[n]
                    }
                    ))
                }
            }, {
                key: "_getValueListFromUser",
                value: function(e) {
                    var t, r = this, a = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : this.projectId, n = [], _ = [], o = "ccw_loading_";
                    return e.forEach((function(e) {
                        var t = "".concat(a, "-").concat(e);
                        r._userCache[t] && r._projectCachedTimeout[t] ? n.push(r._userCache[t]) : (n.push(o + e),
                        _.push(e))
                    }
                    )),
                    _.length > 0 ? null === (t = this.cloudDB) || void 0 === t ? void 0 : t.get({
                        accessKey: this.projectId,
                        primaryKey: a,
                        secondaryKey: this.UserId,
                        filterKeys: _,
                        DBType: _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER
                    }).then((function(e) {
                        return e ? n.map((function(t) {
                            if (t.startsWith(o)) {
                                var n = t.replace(o, "")
                                  , _ = "".concat(a, "-").concat(n);
                                if (Object.prototype.hasOwnProperty.call(e, n)) {
                                    var c = e[n];
                                    return r._userCache[_] = c,
                                    r._refreshProjectCacheTimeout(_),
                                    c
                                }
                                return ""
                            }
                            return t
                        }
                        )) : null
                    }
                    )) : n
                }
            }, {
                key: "setValueToDB",
                value: function(e) {
                    var t = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.KEY)
                      , r = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.VALUE);
                    e.DB === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER ? this._setValueToUser(t, r) : e.DB === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT && this._setValueToProject(t, r)
                }
            }, {
                key: "getValueFromDB",
                value: function(e) {
                    var t = e.KEY
                      , r = e.DB
                      , a = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(t);
                    return r === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER ? this._getValueFromUser(a) : r === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT ? this._getValueFromProject(a) : ""
                }
            }, {
                key: "getValueFromOtherProjectDB",
                value: function(e) {
                    var t = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.KEY)
                      , r = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.PROJECT_ID);
                    return e.DB === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER ? this._getValueFromUser(t, r) : e.DB === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT ? this._getValueFromProject(t, r) : ""
                }
            }, {
                key: "_generateBackupKey",
                value: function(e, t) {
                    return "backup_".concat(e, "_").concat(t)
                }
            }, {
                key: "_getBackUpValueFromOtherProjectDB",
                value: function(e) {
                    var t = e.PROJECT_ID
                      , r = e.KEY
                      , a = e.DB
                      , n = this._generateBackupKey(t, r);
                    return this.getValueFromDB({
                        KEY: n,
                        DB: a
                    })
                }
            }, {
                key: "_setBackUpValueWhenReadFromOtherProjectDB",
                value: function(e) {
                    var t = e.PROJECT_ID
                      , r = e.KEY
                      , a = e.VALUE
                      , n = e.DB
                      , _ = this._generateBackupKey(t, r)
                      , o = _ + (n === _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER ? "-u" : "-p");
                    this._backupValueCache[o] !== a && (this._backupValueCache[o] = a,
                    this.setValueToDB({
                        KEY: _,
                        VALUE: a,
                        DB: n
                    }))
                }
            }, {
                key: "getValueFromOtherProjectDB_V2",
                value: (_getValueFromOtherProjectDB_V = _asyncToGenerator(_regeneratorRuntime().mark((function e(t) {
                    var r;
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                return e.prev = 0,
                                e.next = 3,
                                this.getValueFromOtherProjectDB(t);
                            case 3:
                                return (r = e.sent) && this._setBackUpValueWhenReadFromOtherProjectDB(_objectSpread(_objectSpread({}, t), {}, {
                                    VALUE: r
                                })),
                                e.abrupt("return", r);
                            case 8:
                                return e.prev = 8,
                                e.t0 = e.catch(0),
                                e.abrupt("return", this.__getBackUpValueFromOtherProjectDB_V2(t));
                            case 11:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e, this, [[0, 8]])
                }
                ))),
                function(e) {
                    return _getValueFromOtherProjectDB_V.apply(this, arguments)
                }
                )
            }, {
                key: "_getValueListFromDB",
                value: (_getValueListFromDB2 = _asyncToGenerator(_regeneratorRuntime().mark((function e(t, r) {
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                if (r !== _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.USER) {
                                    e.next = 2;
                                    break
                                }
                                return e.abrupt("return", this._getValueListFromUser(t));
                            case 2:
                                if (r !== _api_cloudDB__WEBPACK_IMPORTED_MODULE_3__.w.PROJECT) {
                                    e.next = 7;
                                    break
                                }
                                if (!(t.length > 50)) {
                                    e.next = 6;
                                    break
                                }
                                return this.runtime.logSystem.error(this._formatMessage("CCWData.getValueListFromDB.MAX")),
                                e.abrupt("return", this._formatMessage("CCWData.getValueListFromDB.MAX"));
                            case 6:
                                return e.abrupt("return", this._getListValueFromProject(t));
                            case 7:
                                return e.abrupt("return", null);
                            case 8:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e, this)
                }
                ))),
                function(e, t) {
                    return _getValueListFromDB2.apply(this, arguments)
                }
                )
            }, {
                key: "getValueListFromDB",
                value: (_getValueListFromDB3 = _asyncToGenerator(_regeneratorRuntime().mark((function e(t, r) {
                    var a, n, _;
                    return _regeneratorRuntime().wrap((function(e) {
                        for (; ; )
                            switch (e.prev = e.next) {
                            case 0:
                                if (a = t.KEY_LIST,
                                n = t.DB,
                                _ = this.lookupListByIdOrName(a, r)) {
                                    e.next = 5;
                                    break
                                }
                                return console.warn("[CCWData]⚠️ Get value list from DB: source list not found"),
                                e.abrupt("return", "");
                            case 5:
                                return e.abrupt("return", this._getValueListFromDB(_.value, n).then((function(e) {
                                    return Array.isArray(e) ? e.join(",") : null != e ? e : ""
                                }
                                )));
                            case 6:
                            case "end":
                                return e.stop()
                            }
                    }
                    ), e, this)
                }
                ))),
                function(e, t) {
                    return _getValueListFromDB3.apply(this, arguments)
                }
                )
            }, {
                key: "getValueListFromDBToList",
                value: function(e, t) {
                    var r = e.TO_LIST;
                    !r && e && e.LIST && "object" === _typeof(e.LIST) && e.LIST.id && (r = e.LIST.id);
                    var a = this.lookupListByIdOrName(r, t);
                    if (a) {
                        var n = this.lookupListByIdOrName(e.KEY_LIST, t);
                        if (n)
                            return this._getValueListFromDB(n.value, e.DB).then((function(e) {
                                Array.isArray(e) && (a.value = e)
                            }
                            ));
                        console.warn("[CCWData]⚠️ Get value list from DB: source list not found")
                    } else
                        console.warn("[CCWData]⚠️ Get value list from DB: list to fill not found")
                }
            }, {
                key: "sendPlayEventCode",
                value: function(e) {
                    this.runtime.ccwAPI.sendPlayEventCode([8592293917, 1], {
                        code: e.CODE,
                        data: e.DATA
                    })
                }
            }, {
                key: "isValid",
                value: function(e) {
                    var t = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.VALUE)
                      , r = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.TYPE);
                    try {
                        var a = JSON.parse(t);
                        if (null === a)
                            return !1;
                        if ("any" === r)
                            return !0;
                        if ("object" === r)
                            return !Array.isArray(a);
                        if ("array" === r)
                            return Array.isArray(a)
                    } catch (e) {
                        return !1
                    }
                    return !1
                }
            }, {
                key: "getValueInJSON",
                value: function getValueInJSON(args) {
                    var key = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.KEY), json = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.JSON), jsonObj;
                    try {
                        jsonObj = JSON.parse(json)
                    } catch (e) {
                        return "error: ".concat(e.message)
                    }
                    if (/[()=]/gm.test(key))
                        return "error: invalid key ".concat(key, ", cannot contain ()=");
                    var key2 = "jsonObj[".concat(key, "]"), rtObj;
                    Array.isArray(jsonObj) ? key = key.startsWith("[") ? "jsonObj".concat(key) : "jsonObj[".concat(key, "]") : /\s/gm.test(key) ? (console.warn("[CCW Data] warning: invalid key ".concat(key, ", space and dot cannot be used together")),
                    key = 'jsonObj["'.concat(key, '"]')) : key = "jsonObj.".concat(key);
                    try {
                        rtObj = eval(key)
                    } catch (e) {
                        try {
                            rtObj = eval(key2)
                        } catch (e) {
                            return "error: key or expression invalid"
                        }
                    }
                    return "object" === _typeof(rtObj) ? JSON.stringify(rtObj) : rtObj
                }
            }, {
                key: "_findValueByKeyString",
                value: function(e, t) {
                    var r = ""
                      , a = e;
                    return _tokenizr__WEBPACK_IMPORTED_MODULE_5__.Z.input(t),
                    _tokenizr__WEBPACK_IMPORTED_MODULE_5__.Z.tokens().forEach((function(e) {
                        if ("getter" !== e.type && "EOF" !== e.type)
                            try {
                                a = a["".concat(e.value)],
                                r += "[".concat(e.value, "]")
                            } catch (t) {
                                throw new Error("cannot find key '".concat(e.value, "', current Object").concat(r, " is '").concat(JSON.stringify(a), "'"))
                            }
                    }
                    )),
                    a
                }
            }, {
                key: "_logError",
                value: function(e, t) {
                    var r = this._formatMessage({
                        id: "CCWData.name",
                        default: "CCWData"
                    });
                    if (e) {
                        var a = this._formatMessage({
                            id: e
                        });
                        r = "".concat(r, "-").concat(a)
                    }
                    this.runtime.logSystem.error("Error:".concat(r, "\n  ").concat(t))
                }
            }, {
                key: "getValueInJSON_2",
                value: function(e) {
                    var t = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.KEY)
                      , r = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.JSON);
                    try {
                        var a = JSON.parse(r)
                          , n = this._findValueByKeyString(a, t);
                        return "object" === _typeof(n) ? JSON.stringify(n) : n
                    } catch (e) {
                        return this._logError("CCWData.getValueInJSON_2", e.toString()),
                        "error: ".concat(e.message)
                    }
                }
            }, {
                key: "setValueInJSON",
                value: function setValueInJSON(args) {
                    var key = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.KEY), value = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.VALUE), json = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(args.JSON), jsonObj;
                    try {
                        jsonObj = JSON.parse(json)
                    } catch (e) {
                        return "error: ".concat(e.message)
                    }
                    if (/[()=]/gm.test(key))
                        return "error: invalid key ".concat(key, ", cannot contain ()=");
                    var valueObj = value;
                    if (/^[\[].*?[\]]$/gm.test(value) || /^[\{].*?[\}]$/gm.test(value))
                        try {
                            valueObj = JSON.parse(value)
                        } catch (e) {}
                    "string" == typeof valueObj && /^-?\d*\.?\d*$/gm.test(valueObj) && (valueObj = Number(valueObj));
                    try {
                        Array.isArray(jsonObj) ? jsonObj[key] = valueObj : /[\.\[\]]/gm.test(key) ? (valueObj instanceof Object ? (valueObj = JSON.stringify(valueObj),
                        valueObj = "JSON.parse('".concat(valueObj, "')")) : "string" == typeof valueObj && (valueObj = "'".concat(valueObj, "'")),
                        eval("jsonObj.".concat(key, " = ").concat(valueObj))) : jsonObj[key] = valueObj
                    } catch (e) {
                        return "error: key or expression invalid"
                    }
                    return JSON.stringify(jsonObj)
                }
            }, {
                key: "setValueInJSON_2",
                value: function(e) {
                    var t, r = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.KEY), a = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.VALUE), n = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.JSON);
                    try {
                        t = JSON.parse(n)
                    } catch (e) {
                        return "error: ".concat(e.message)
                    }
                    if (/[()=]/gm.test(r))
                        return "error: invalid key ".concat(r, ", cannot contain ()=");
                    var _ = a;
                    if (/^[\[].*?[\]]$/gm.test(a) || /^[\{].*?[\}]$/gm.test(a))
                        try {
                            _ = JSON.parse(a)
                        } catch (e) {}
                    "string" == typeof _ && /^-?\d*\.?\d*$/gm.test(_) && (_ = Number(_));
                    var o = ""
                      , c = t;
                    _tokenizr__WEBPACK_IMPORTED_MODULE_5__.Z.input(r);
                    try {
                        return _tokenizr__WEBPACK_IMPORTED_MODULE_5__.Z.tokens().forEach((function(e, t, r) {
                            if ("getter" !== e.type && "EOF" !== e.type)
                                if (o += "[".concat(e.value, "]"),
                                t !== r.length - 2) {
                                    if (!c)
                                        throw new Error("cannot set value for key '".concat(e.value, "', current Object").concat(o, " is 'undefined'"));
                                    c = c[e.value]
                                } else {
                                    if ((0,
                                    lodash_es__WEBPACK_IMPORTED_MODULE_8__.Z)(c) && Number.isNaN(e.value))
                                        throw new Error("cannot set value for key '".concat(e.value, "', current Object").concat(o, " is an array, use index instead"));
                                    c[e.value] = _
                                }
                        }
                        )),
                        JSON.stringify(t)
                    } catch (e) {
                        return this._logError("CCWData.setValueInJSON_2", e.toString()),
                        "error: ".concat(e.message)
                    }
                }
            }, {
                key: "lookupListByIdOrName",
                value: function(e, t) {
                    var r = t.target.lookupVariableById(e) || t.target.lookupVariableByNameAndType(e, "list");
                    if (!r) {
                        var a = t.stackFrame.globalTarget;
                        if (!a)
                            return null;
                        var n = a.lookupVariableById(e) || a.lookupVariableByNameAndType(e, "list");
                        if (n) {
                            var _ = t.target.isStage ? "Stage: ".concat(n.name) : n.name;
                            r = t.target.lookupOrCreateList((0,
                            _util_gandi_util__WEBPACK_IMPORTED_MODULE_4__.sq)(), _)
                        }
                    }
                    return r
                }
            }, {
                key: "fillJSONArrayToList",
                value: function(e, t) {
                    var r, a = scratch_vm_src_util_cast__WEBPACK_IMPORTED_MODULE_2___default().toString(e.JSON);
                    if ("empty" !== e.LIST) {
                        try {
                            r = JSON.parse(a)
                        } catch (e) {
                            return void console.warn("[CCWData]⚠️ fill list: invalid JSON String ".concat(e.message))
                        }
                        if (Array.isArray(r)) {
                            try {
                                r = r.map((function(e) {
                                    return e instanceof Object ? JSON.stringify(e) : e
                                }
                                ))
                            } catch (e) {
                                return void console.warn("[CCWData]⚠️ fill list: JSON Array cannot be converted to string ".concat(e.message))
                            }
                            var n = this.lookupListByIdOrName(e.LIST, t);
                            if (n) {
                                var _ = [];
                                "insert" === e.METHOD && (_ = _.concat(n.value)),
                                n.value = _.concat(r)
                            } else
                                console.warn("[CCWData]⚠️ fill list: list not found")
                        } else
                            console.warn("[CCWData]⚠️ fill list: JSON is not an array")
                    } else
                        console.warn("[CCWData]⚠️ fill list: list is not selected")
                }
            }, {
                key: "getJSONArrayFromList",
                value: function(e, t) {
                    if ("empty" === e.LIST)
                        return console.warn("[CCWData]⚠️ get JSON from a list: list is not selected"),
                        "error: list is not selected";
                    var r = this.lookupListByIdOrName(e.LIST, t);
                    if (!r)
                        return console.warn("[CCWData]⚠️ get JSON from a list: list not found"),
                        "error: list not found";
                    var a = [];
                    "convert" === e.METHOD ? r.value.forEach((function(e) {
                        try {
                            a.push(JSON.parse(e))
                        } catch (t) {
                            a.push(e)
                        }
                    }
                    )) : a = r.value;
                    try {
                        return JSON.stringify(a)
                    } catch (e) {
                        return console.warn("[CCWData]⚠️ get JSON from a list: JSON Array cannot be converted to string ".concat(e.message)),
                        "error: JSON Array cannot be converted to string"
                    }
                }
            }, {
                key: "setProjectDataCachePolicy",
                value: function(e) {
                    var t = e.KEY
                      , r = e.CACHE;
                    this._setProjectDataCachePolicy(this._getCacheKey(t), r)
                }
            }, {
                key: "setProjectDataCachePolicyByBatch",
                value: function(e) {
                    var t = this
                      , r = e.KEYS_STR
                      , a = e.CACHE;
                    r.split(",").forEach((function(e) {
                        t._setProjectDataCachePolicy(t._getCacheKey(e), a)
                    }
                    ))
                }
            }, {
                key: "findAllList",
                value: function() {
                    var e = []
                      , t = this.runtime._stageTarget.variables;
                    Object.keys(t).forEach((function(r) {
                        "list" === t[r].type && e.push({
                            text: "".concat(t[r].name),
                            value: t[r].id
                        })
                    }
                    ));
                    try {
                        t = this.runtime._editingTarget.variables
                    } catch (e) {
                        t = "e"
                    }
                    return "e" !== t && this.runtime._editingTarget !== this.runtime._stageTarget && Object.keys(t).forEach((function(r) {
                        "list" === t[r].type && e.push({
                            text: "[PRIVATE]".concat(t[r].name),
                            value: t[r].id
                        })
                    }
                    )),
                    0 === e.length && e.push({
                        text: "-",
                        value: "empty"
                    }),
                    e
                }
            }]),
            CCWData
        }()
    }
    ,
    85051: (e, t, r) => {
        r.d(t, {
            Z: () => _
        });
        var a = r(47285)
          , n = new (r.n(a)());
        n.rule(/"((?:\\"|[^\r\n])*)"/, (function(e, t) {
            e.accept("keyString", t[1])
        }
        )),
        n.rule(/(?<!\.)\.(?!\.)/, (function(e, t) {
            e.accept("getter")
        }
        )),
        n.rule(/\[([0-9]+|['"]([^'"]*)['"])\]/, (function(e, t) {
            void 0 !== t[2] ? e.accept("keyString", t[2]) : e.accept("keyIndex", t[1])
        }
        )),
        n.rule(/[^\[\].]*/, (function(e, t) {
            "" !== t[0].trim() ? e.accept("keyString") : e.reject()
        }
        ));
        const _ = n
    }
    ,
    49576: (e, t, r) => {
        function a(e) {
            return function(e) {
                if (Array.isArray(e))
                    return _(e)
            }(e) || function(e) {
                if ("undefined" != typeof Symbol && null != e[Symbol.iterator] || null != e["@@iterator"])
                    return Array.from(e)
            }(e) || n(e) || function() {
                throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
            }()
        }
        function n(e, t) {
            if (e) {
                if ("string" == typeof e)
                    return _(e, t);
                var r = Object.prototype.toString.call(e).slice(8, -1);
                return "Object" === r && e.constructor && (r = e.constructor.name),
                "Map" === r || "Set" === r ? Array.from(e) : "Arguments" === r || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r) ? _(e, t) : void 0
            }
        }
        function _(e, t) {
            (null == t || t > e.length) && (t = e.length);
            for (var r = 0, a = new Array(t); r < t; r++)
                a[r] = e[r];
            return a
        }
        r.d(t, {
            O3: () => p,
            ZK: () => s,
            g4: () => i,
            nC: () => c,
            sq: () => l,
            vU: () => u
        });
        var o = function(e) {
            return e.map((function(e) {
                var t = e;
                if (e instanceof Object)
                    try {
                        t = JSON.stringify(e)
                    } catch (e) {
                        t = "TypeError: The message is abnormal and cannot be output."
                    }
                return t
            }
            ))
        }
          , c = function(e, t) {
            var r = {};
            return Object.entries(e).forEach((function(e) {
                var a, _, o = (_ = 2,
                function(e) {
                    if (Array.isArray(e))
                        return e
                }(a = e) || function(e, t) {
                    var r = null == e ? null : "undefined" != typeof Symbol && e[Symbol.iterator] || e["@@iterator"];
                    if (null != r) {
                        var a, n, _ = [], o = !0, c = !1;
                        try {
                            for (r = r.call(e); !(o = (a = r.next()).done) && (_.push(a.value),
                            !t || _.length !== t); o = !0)
                                ;
                        } catch (e) {
                            c = !0,
                            n = e
                        } finally {
                            try {
                                o || null == r.return || r.return()
                            } finally {
                                if (c)
                                    throw n
                            }
                        }
                        return _
                    }
                }(a, _) || n(a, _) || function() {
                    throw new TypeError("Invalid attempt to destructure non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")
                }()), c = o[0], i = o[1];
                r["".concat(t, ".").concat(c)] = i
            }
            )),
            r
        }
          , i = function() {
            for (var e, t = arguments.length, r = new Array(t), n = 0; n < t; n++)
                r[n] = arguments[n];
            var _, c = ["[INFO] : "].concat(a(o(r))).join(" ");
            null === (e = document.GandiBridge) || void 0 === e || e.dispatchEvent(new CustomEvent("trace",{
                detail: {
                    message: c
                }
            })),
            (document.enableTrace || window.debugVM) && (_ = console).info.apply(_, r)
        }
          , s = function() {
            for (var e, t = arguments.length, r = new Array(t), n = 0; n < t; n++)
                r[n] = arguments[n];
            var _, c = ["[WARNING] : "].concat(a(o(r))).join(" ");
            null === (e = document.GandiBridge) || void 0 === e || e.dispatchEvent(new CustomEvent("warn",{
                detail: {
                    message: c
                }
            })),
            document.enableTrace && (_ = console).warn.apply(_, r)
        }
          , u = function() {
            for (var e, t = arguments.length, r = new Array(t), n = 0; n < t; n++)
                r[n] = arguments[n];
            var _, c = ["[ERROR] : "].concat(a(o(r))).join(" ");
            null === (e = document.GandiBridge) || void 0 === e || e.dispatchEvent(new CustomEvent("error",{
                detail: {
                    message: c
                }
            })),
            document.enableTrace && (_ = console).error.apply(_, r)
        }
          , l = function() {
            for (var e = "!#$%()*+,-./:;=?@[]^_`{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", t = e.length, r = [], a = 0; a < 20; a++)
                r[a] = e.charAt(Math.random() * t);
            return r.join("")
        }
          , p = {
            ALL_TAG: "#GANDI_CONST_ALL_TAG#",
            STAGE_TAG: "_stage_",
            MYSELF_TAG: "_myself_"
        }
    }
}]);