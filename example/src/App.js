import React from 'react'
import Login from './Login'
import User from './User'
import 'bootstrap/dist/css/bootstrap.min.css'

class App extends React.Component {
  constructor (props) {
    super(props)
    this.state = {
      loggedIn: false,
      user: null,
    }
  }

  login = (user) => {
    this.setState({
      loggedIn: true,
      user,
    })
  }

  logout = () => {
    this.setState({loggedIn: false})
  }

  render () {
    return this.state.loggedIn ?
        <User onLogout={this.logout} user={this.state.user} />
      : <Login onLogin={this.login} />
  }
}

export default App;
