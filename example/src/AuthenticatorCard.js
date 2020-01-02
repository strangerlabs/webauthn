import React from 'react'
import { Card } from 'react-bootstrap'
import 'bootstrap/dist/css/bootstrap.min.css'

class AuthenticatorCard extends React.Component {
  render () {
    return (
      <Card style={{ width: '32rem' }}>
        <Card.Body>
          <Card.Title>{this.props.authenticator.credID}</Card.Title>
          <Card.Text>
            <p><strong>Format: </strong> {this.props.authenticator.fmt}</p>
            <p><strong>Counter: </strong> {this.props.authenticator.counter}</p>
            <p><strong>Public key: </strong> {this.props.authenticator.publicKey}</p>
          </Card.Text>
        </Card.Body>
      </Card>
    )
  }
}

export default AuthenticatorCard;
