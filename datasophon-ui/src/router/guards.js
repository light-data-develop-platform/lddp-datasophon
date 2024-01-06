import {hasAuthority} from '@/utils/authority-utils'
import {loginIgnore} from '@/router/index'
import {checkAuthorization, setAuthorization} from '@/utils/request'
import NProgress from 'nprogress'
import {axiosGet} from '@/api/request'
import store from '@/store'

NProgress.configure({ showSpinner: false })

/**
 * 进度条开始
 * @param to
 * @param form
 * @param next
 */
const progressStart = (to, from, next) => {
  // start progress bar
  if (!NProgress.isStarted()) {
    NProgress.start()
  }
  next()
}

/**
 * 登录守卫
 * @param to
 * @param form
 * @param next
 * @param options
 */
const loginGuard = async (to, from, next, options) => {
  console.log(to, from, next, options);
  if (!loginIgnore.includes(to) && !checkAuthorization()) {
    const hashStr = window.location.hash
    console.log(hashStr);
    // 如果需要接口授权
    if (hashStr?.includes('lddpToken')) {
      try {
        await userCenterLogin(hashStr.split('?')[1])
        next()
      } catch (e) {
        window.location.reload()
      }
    } else {
      next({ path: '/login' })
    }
  } else {
    next()
  }
}

const userCenterLogin =  (parmas) => {
  axiosGet('/ddh/loginByLddpToken?' + parmas).then((res) => {
    console.log(res);
    if (res.code === 200) {
      setAuthorization({ sessionId: res.data.sessionId })
      store.commit('account/setUser', res.userInfo)
      loadRoutes()
      store.commit('setting/setIsCluster', '')
      this.$router.push('/colony-manage/colony-list')
      // this.$message.success("登录成功", 3);
    }
  })
}


/**
 * 权限守卫
 * @param to
 * @param form
 * @param next
 * @param options
 */
const authorityGuard = (to, from, next, options) => {
  const {store, message} = options
  const permissions = store.getters['account/permissions']
  const roles = store.getters['account/roles']
  if (!hasAuthority(to, permissions, roles)) {
    message.warning(`对不起，您无权访问页面: ${to.fullPath}，请联系管理员`)
    next({path: '/403'})
    // NProgress.done()
  } else {
    next()
  }
}

/**
 * 混合导航模式下一级菜单跳转重定向
 * @param to
 * @param from
 * @param next
 * @param options
 * @returns {*}
 */
const redirectGuard = (to, from, next, options) => {
  const clusterId = localStorage.getItem('clusterId')
  const isCluster = localStorage.getItem('isCluster')
  console.log(clusterId, isCluster, 'dsadasdsada')
  const {store} = options
  const getFirstChild = (routes) => {
    const route = routes[0]
    if (!route.children || route.children.length === 0) {
      return route
    }
    return getFirstChild(route.children)
  }
  if (store.state.setting.layout === 'mix') {
    const firstMenu = store.getters['setting/firstMenu']
    if (firstMenu.find(item => item.fullPath === to.fullPath)) {
      store.commit('setting/setActivatedFirst', to.fullPath)
      const subMenu = store.getters['setting/subMenu']
      if (subMenu.length > 0) {
        const redirect = getFirstChild(subMenu)
        return next({path: redirect.fullPath})
      }
    }
  }
  next()
}

/**
 * 进度条结束
 * @param to
 * @param form
 * @param options
 */
const progressDone = () => {
  // finish progress bar
  NProgress.done()
}

export default {
  beforeEach: [progressStart, loginGuard, authorityGuard, redirectGuard],
  afterEach: [progressDone]
}
