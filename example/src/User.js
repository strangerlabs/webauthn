import React from 'react'
import { Container, Row, Col, Button } from 'react-bootstrap'
import AuthenticatorCard from './AuthenticatorCard'
import Client from 'webauthn/client'
import 'bootstrap/dist/css/bootstrap.min.css'

class User extends React.Component {
  constructor (props) {
    super(props)

    this.state = {
      authenticators: []
    }

    fetch('authenticators', {
      method: 'GET',
      credentials: 'include',
    }).then(response => {
      if (response.status !== 200) {
        console.error(response.message)
        return
      }
      return response.json()
    }).then(authenticators => {
      this.setState({ authenticators })
    })
  }

  logout = () => {
    (new Client()).logout().then(() => this.props.onLogout())
  }

  render () {
    return (
      <Container>
        <Row style={{ paddingTop: 80}}>
          <Col>
            <h2>Welcome {this.props.user.username}</h2>
            <h3>Your authenticators:</h3>
          </Col>
          <Col className="text-right">
            <Button variant="primary" onClick={this.logout}>Log Out</Button>
          </Col>
        </Row>
        {this.state.authenticators.map(authenticator => <Row key={authenticator.credID}>
          <Col><AuthenticatorCard authenticator={authenticator} /></Col>
        </Row>)}
      </Container>
    )
  }
}

export default User;
