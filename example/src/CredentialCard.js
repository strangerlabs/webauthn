import React from 'react'
import { Card } from 'react-bootstrap'
import 'bootstrap/dist/css/bootstrap.min.css'

class CredentialCard extends React.Component {
  render () {
    return (
      <Card>
        <Card.Body>
          <Card.Title>{this.props.credential.credID}</Card.Title>
          <Card.Text>
            <p><strong>Format: </strong> {this.props.credential.fmt}</p>
            <p><strong>Counter: </strong> {this.props.credential.counter}</p>
            <p><strong>Public key: </strong> {this.props.credential.publicKey}</p>
          </Card.Text>
        </Card.Body>
      </Card>
    )
  }
}

export default CredentialCard;
