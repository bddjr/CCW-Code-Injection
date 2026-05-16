// https://assets.ccw.site/extension/dangerousCCWData
(function (_Scratch) {
  const { ArgumentType, BlockType, TargetType, Cast, translate, extensions, runtime } = _Scratch;
  const extensionId = 'dangerousCCWData';
  // （并不safe)
  function saferEval(code, args = {}) {
    // 临时禁用部分危险API
    const disabledAPIs = [
      'fetch',
      'XMLHttpRequest',
      'WebSocket',
      'EventSource',
      'Worker',
      'alert',
      'confirm',
      'prompt',
      'setTimeout',
      'setInterval',
      'Function',
      'Image',
      'Audio',
      'Video',
      'open',
    ];
    const origAPIs = {};

    const OrigFunction = window.Function;
    // 保存并禁用危险API
    disabledAPIs.forEach((api) => {
      origAPIs[api] = window[api];
      window[api] = null;
    });

    try {
      // 提取参数的键和值，用于传递给new Function
      const argKeys = Object.keys(args);
      const argValues = Object.values(args);
      const funcCode = `const globalThis = null;
          const window = null;
          const document = null;
          const alert = null;
          const confirm = null;
          const prompt = null;
          const fetch = null;
          const XMLHttpRequest = null;
          const localStorage = null;
          const sessionStorage = null;
          const Image = null;
          const Audio = null;
          const Video = null;
          const Worker = null;
          const Function = null;
          const open = null;
          const history = null;
          const location = null;
          const navigator = null;
          ${code}`;

      // 创建函数：参数为argKeys，函数体为code
      // new Function的作用域是全局，不会访问当前函数作用域
      const func = new OrigFunction(...argKeys, funcCode);
      // 执行函数并返回结果
      return func(...argValues);
    } finally {
      // 恢复禁用的API
      disabledAPIs.forEach((api) => {
        window[api] = origAPIs[api];
      });
    }
  }

  class CCWData {
    constructor(runtime) {
      this._formatMessage = runtime.getFormatMessage({
        'zh-cn': {
          'CCWData.name': '危险云数据',
          'CCWData.setValueInJSON': '（⚠️ 危险，仅用于作品兼容）设置[JSON]中的[KEY]的值为[VALUE]',
          'CCWData.getValueInJSON': '（⚠️ 危险，仅用于作品兼容）获得[KEY]在[JSON]中的值',
        },
        en: {
          'CCWData.name': 'Dangerous Cloud Data',
          'CCWData.getValueInJSON': '(⚠️ dangerous) get [KEY] in [JSON]',
          'CCWData.setValueInJSON': '(⚠️ dangerous) set [VALUE] of key [KEY] in [JSON]',
        },
      });
    }

    block_getValueInJSON = () => {
      return {
        opcode: 'getValueInJSON',
        text: this._formatMessage({
          id: 'CCWData.getValueInJSON',
        }),
        blockType: BlockType.REPORTER,
        disableMonitor: true,
        arguments: {
          KEY: {
            type: ArgumentType.STRING,
            defaultValue: 'key',
          },
          JSON: {
            type: ArgumentType.STRING,
            defaultValue: '{"key":"value"}',
          },
        },
      };
    };

    block_setValueInJSON = () => {
      return {
        opcode: 'setValueInJSON',
        text: this._formatMessage({
          id: 'CCWData.setValueInJSON',
        }),
        blockType: BlockType.REPORTER,
        disableMonitor: true,
        arguments: {
          KEY: {
            type: ArgumentType.STRING,
            defaultValue: 'key',
          },
          VALUE: {
            type: ArgumentType.STRING,
            defaultValue: 'new value',
          },
          JSON: {
            type: ArgumentType.STRING,
            defaultValue: '{"key":"value"}',
          },
        },
      };
    };

    /** Ext Info */
    getInfo() {
      return {
        id: extensionId,
        name: this._formatMessage({
          id: 'CCWData.name',
          default: 'CCWData',
        }),
        color1: '#ED35A3',
        // menuIconURI: icon,
        // blockIconURI: icon,
        blocks: [
          // this.setValueBlock(),
          // this.getValueBlock(),
          this.block_getValueInJSON(),
          this.block_setValueInJSON(),
        ],
        menus: {},
      };
    }

    getValueInJSON(args) {
      let key = Cast.toString(args.KEY);
      const json = Cast.toString(args.JSON);
      let jsonObj;
      try {
        jsonObj = JSON.parse(json);
      } catch (e) {
        return `error: ${e.message}`;
      }

      // process key into evaluable string
      if (/[()=]/gm.test(key)) {
        return `error: invalid key ${key}, cannot contain ()=`;
      }

      const key2 = `jsonObj[${key}]`;
      // process key when  json is an array
      if (Array.isArray(jsonObj)) {
        if (key.startsWith('[')) {
          key = `jsonObj${key}`;
        } else {
          key = `jsonObj[${key}]`;
        }
      } else if (/\s/gm.test(key)) {
        // return `error: invalid key ${key}, cannot contain space`;
        console.warn(`[CCW Data] warning: invalid key ${key}, space and dot cannot be used together`);
        key = `jsonObj["${key}"]`;
      } else {
        key = `jsonObj.${key}`;
      }

      let rtObj;
      // try eval
      try {
        // console.info(key, jsonObj);
        rtObj = saferEval(`return ${key}`, { jsonObj });
      } catch (e) {
        // Try eval with key2
        try {
          // console.info(key2, jsonObj);
          rtObj = saferEval(`return ${key2}`, { jsonObj });
          // eslint-disable-next-line no-empty
        } catch (e) {
          return `error: key or expression invalid`;
        }
      }
      if (typeof rtObj === 'object') {
        return JSON.stringify(rtObj);
      }
      return rtObj;
    }

    setValueInJSON(args) {
      const key = Cast.toString(args.KEY);
      const value = Cast.toString(args.VALUE);
      const json = Cast.toString(args.JSON);
      let jsonObj;
      try {
        jsonObj = JSON.parse(json);
      } catch (e) {
        return `error: ${e.message}`;
      }

      // process key into evaluable string
      if (/[()=]/gm.test(key)) {
        return `error: invalid key ${key}, cannot contain ()=`;
      }

      // try convert value to json object
      // eslint-disable-next-line no-new-wrappers
      let valueObj = value;
      if (/^[\[].*?[\]]$/gm.test(value) || /^[\{].*?[\}]$/gm.test(value)) {
        // is json object
        // console.info('is json object');
        try {
          valueObj = JSON.parse(value);
        } catch (e) {
          // do nothing
        }
      }

      // console.info(typeof valueObj);

      if (typeof valueObj === 'string') {
        // convert to number if possible
        if (/^-?\d*\.?\d*$/gm.test(valueObj)) {
          valueObj = Number(valueObj);
        }
      }

      // try set
      try {
        if (Array.isArray(jsonObj)) {
          jsonObj[key] = valueObj;
        } else if (/[\.\[\]]/gm.test(key)) {
          // contains . or [ or ], should eval
          // console.info(`jsonObj.${key} = ${valueObj}`);
          saferEval(`jsonObj.${key} = valueObj;`, { jsonObj, valueObj });
        } else {
          jsonObj[key] = valueObj;
        }
      } catch (e) {
        return `error: key or expression invalid`;
      }
      return JSON.stringify(jsonObj);
    }
  }

  extensions.register(new CCWData(runtime));
})(Scratch);
